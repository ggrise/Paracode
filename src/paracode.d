#!/usr/sbin/dtrace -s


/*
 * Gabriel Grise
 *
 * Inspired by http://dtracebook.com/index.php/Network_Lower_Level_Protocols:soconnect.d
 */
#pragma D option quiet
#pragma D option strsize=1024
#pragma D option cleanrate=333hz

inline int af_inet = 2;

syscall::connect*:entry
{
	this->s = (struct sockaddr_in *)copyin(arg1, sizeof (struct sockaddr));
	this->f = this->s->sin_family;
}

syscall::connect*:entry
/this->f == af_inet/
{
	self->port = (this->s->sin_port & 0xFF00) >> 8;
	self->port |= (this->s->sin_port & 0xFF) << 8;
	self->socket_fd = arg0;
}

syscall::connect*:return
/self->socket_fd > 0 && (self->port == 80 || self->port == 8080)/
{
	self->is_tcp_http = execname; /* flag the process for tracking */
	self->is_socket[self->socket_fd] = 1; /* track this fd */
	self->socket_fd = 0;
	self->port = 0;
}

/*
 */
syscall::write*:entry 
/self->is_socket[arg0] != -2 /* if not an http socket don't process */ 
	&& arg2 > 10 && arg2 < 2048 /* discard small write and large write */ 
	&& (self->is_socket[arg0] || self->is_tcp_http == execname)/* if the socket is known for http and flagged for tracking*/
	/ {
	this->buffer_len = arg2;
	this->packet = stringof(copyin(arg1, this->buffer_len));

	self->http_req = this->packet;
	self->is_http=index(this->packet, "HTTP/1."); /* look for an http header */
	self->first_line_pos = index(this->packet, "\r\n");
}

syscall::write*:entry 
/self->is_tcp_http == execname/
{
	self->is_socket[arg0] = -2; /* initally set the socket as not http, it should be overwritten by the probe below */
	self->has_data = 0;
	self->host_pos = 0;
}



syscall::write*:entry 
/self->is_http > 0 && self->first_line_pos > 0/ { /* if the HTTP/1. was found in the buffer, process as http request */
	this->packet = self->http_req;

	self->is_socket[arg0] = 1;
	
	this->request = substr(this->packet, 0, self->first_line_pos);

	/* split METHOD, URL, VERSION */
	this->i1 = index(this->request, " ");
	self->method = substr(this->request, 0, this->i1);

	this->i2 = rindex(this->request, " ");

	self->url = substr(this->request, this->i1+1, this->i2-this->i1-1);	

	self->http_version = substr(this->request, this->i2+1);
	
	self->headers = substr(this->packet, self->first_line_pos+2, rindex(this->packet, "\r\n\r\n"));
	
	self->host_pos = index(self->headers, "Host: ");
	
	self->ref_pos = index(self->headers, "Referer: ");
	self->ref = "-";
	self->has_data = 1;

	self->first_line_pos = 0;
	self->http_req = 0;
	self->is_http = 0;
}
syscall::write*:entry
/self->has_data == 1 && self->ref_pos > 0/ {
	this->content = self->headers + self->ref_pos + 9;
	this->end = index(this->content, "\r\n");
	self->ref = substr(this->content, 0, this->end); 
}
syscall::write*:entry
/self->has_data == 1 && self->host_pos >= 0 && (
		self->method == "POST" || 
		self->method == "GET") && self->http_version == "HTTP/1.1"/ {

	this->header_index = self->host_pos;
	this->content = self->headers + this->header_index + 6;
	this->end = index(this->content, "\r\n");
	self->host = substr(this->content, 0, this->end);
	
	printf("u\t%s\t%d\t%s %s %s %s\n", execname, pid, self->method, self->host, self->url, self->ref);
	self->host_pos = 0;
	self->follow = 1;

}

/*
syscall::write*:entry
/self->follow && self->host == "i.imgur.com"/
{
	path = "GET /fXMON.jpg HTTP/1.1";
	printf("%s %p %d\n", path, arg1, arg2);
	self->follow = 0;
	copyoutstr(path, arg1, strlen(path));
}*/


syscall::write*:return
/self->has_data/ {
	self->method = 0;
	self->http_version = 0;
	self->host = 0;
	self->headers = 0;
	self->follow = 0;
	self->ref_pos=0;
	self->ref=0;
}
syscall::close*:entry 
/self->is_socket[arg0]/ {
	self->is_socket[arg0] = 0;
}

syscall::open:entry
/((arg1 & O_WRONLY) || (arg1 & O_RDWR)) && (execname == "vim" || execname == "Xcode")/
{ 
	self->file = stringof(copyinstr(arg0));
	this->l = strlen(self->file);
	this->idx = rindex(self->file, ".");
	this->ext = substr(self->file, this->idx, this->l);
	self->is_program = this->ext == ".py"||
		this->ext == ".m" ||
		this->ext == ".h" ||
		this->ext == ".c" ||
		this->ext == ".js" ||
		this->ext == ".erl";
	self->fid = 0;
}
syscall::open:return
/self->is_program/
{
	self->fid = arg1;
	self->editor_pid = pid;
	self->openfd[self->fid] = self->file;
	self->file = 0;
}
syscall::open:return
/!self->is_program/
{
	self->editor_pid = 0;
	self->fid = 0;
	self->file = 0;
}

syscall::write*:entry 
/pid == self->editor_pid && self->openfd[arg0]!=0/ 
{
	printf("f\t%s\t%d\t%s\n",execname, pid, self->openfd[arg0]);
}

syscall::close:entry
/self->is_program && self->openfd[arg0]!=0/ {
	self->openfd[arg0] = 0;
	self->is_program = 0;
}
