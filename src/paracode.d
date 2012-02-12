#!/usr/sbin/dtrace -ws
/*
 * Gabriel Grise
 *
 * Inspired by http://dtracebook.com/index.php/Network_Lower_Level_Protocols:soconnect.d
 */
#pragma D option quiet
#pragma D option strsize=1024

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
/self->socket_fd > 0 && self->port == 80 || self->port == 443/
{
	self->is_tcp_http = execname; /* flag the process for tracking */
	self->is_socket[self->socket_fd] = 1; /* track this fd */
	self->socket_fd = 0;
}

/*
 */
syscall::write*:entry 
/self->is_socket[arg0] != -2 /* if not an http socket don't process */ 
	&& arg2 > 10 && arg2 < 2048 /* discard small write and large write */ 
	&& (self->is_socket[arg0] || self->is_tcp_http == execname)/* if the socket is known for http and flagged for tracking*/
	/ {
	buffer_len = arg2;
	packet = stringof(copyin(arg1, buffer_len));

	self->http_req = packet;
	self->is_http=index(packet, "HTTP/1."); /* look for an http header */
	self->first_line_pos = index(packet, "\r\n");
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
	packet = self->http_req;

	self->is_socket[arg0] = 1;
	
	request = substr(packet, 0, self->first_line_pos);

	/* split METHOD, URL, VERSION */
	i1 = index(request, " ");
	self->method = substr(request, 0, i1);

	i2 = rindex(request, " ");

	self->url = substr(request, i1+1, i2-i1-1);	

	self->http_version = substr(request, i2+1);
	
	self->headers = substr(packet, self->first_line_pos+2, rindex(packet, "\r\n\r\n"));
	
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
	content = self->headers + self->ref_pos + 9;
	end = index(content, "\r\n");
	self->ref = substr(content, 0, end); 
}
syscall::write*:entry
/self->has_data == 1 && self->host_pos >= 0 && (
		self->method == "POST" || 
		self->method == "GET") && self->http_version == "HTTP/1.1"/ {

	header_index = self->host_pos;
	content = self->headers + header_index + 6;
	end = index(content, "\r\n");
	self->host = substr(content, 0, end);
	
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

syscall::open:entry
/execname == "vim" || execname == "Xcode"/
{ 
	self->file = stringof(copyinstr(arg0));
	l = strlen(self->file);
	idx = rindex(self->file, ".");
	ext = substr(self->file, idx, l);
	self->is_program = ext == ".py"||
		ext == ".m" ||
		ext == ".h" ||
		ext == ".c" ||
		ext == ".js" ||
		ext == ".erl";
	self->fid = 0;
}
syscall::open:return
/self->is_program/
{
	self->fid = arg1;
	self->editor_pid = pid;
	self->openfd[self->fid] = self->file;
}
syscall::open:return
/!self->is_program/
{
	self->editor_pid = 0;
	self->openfd[self->fid] = 0;
	self->fid = 0;
	self->file = 0;
}

syscall::write*:entry 
/pid == self->editor_pid && self->openfd[arg0]!=0/ 
{
	self->is_program = 0;
	printf("f\t%s\t%d\t%s\n",execname, pid, self->openfd[arg0]);
}

syscall::close:entry
/pid == self->editor_pid && self->openfd[arg0]!=0/ {
	self->openfd[arg0] = 0;
	self->file = 0;
}
