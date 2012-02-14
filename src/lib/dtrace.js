var util   = require('util'),
    spawn = require('child_process').spawn,
	events = require('events');


var DtraceConsumer = function() {

	events.EventEmitter.call(this);
	
	var _dtrace    = spawn('./paracode.d', []);
	
	process.on('SIGTERM', function () {
		_dtrace.kill(dtrace);
	});

	this.dtrace = _dtrace;

	var buffer = "";
	
	this.process_http = function(httpinfo) {
		var execname = httpinfo[0];
		var pid = parseInt(httpinfo[1]);
		var httptuple = httpinfo[2].split(" ");

		this.emit('url.visit', {execname: execname, pid: pid, time: new Date(), info: {method: httptuple[0], host: httptuple[1], path: httptuple[2], referer:httptuple[3] == "-" ? null : httptuple[3]}});
	}

	this.process_file = function(data) {
		var execname = data[0];
		var pid = data[1];
		var file = data[2];
		this.emit('file.edit', {execname: execname, pid: pid, time: new Date(), info: {filename: file}});
	}
	this.process_output = function(data) {
		var info = data.split("\t");
		if(info[0] == "f") {
			this.process_file(info.slice(1, info.length))
		} else {
			this.process_http(info.slice(1, info.length))
		}
	}
	var self = this;
	this.dtrace.stdout.on('data', function (data) {
		buffer += data.asciiSlice(0,data.length) 
		var idx = -1;
		
		idx = buffer.indexOf("\n");
		while(idx != -1) {
			var record = buffer.substring(0, idx);
			self.process_output(record);
			buffer = buffer.substring(idx+1);
			idx = buffer.indexOf("\n");
		}

	});
	this.dtrace.stderr.on('data', function (data) {
	  console.log('stderr: ' + data);
	});

	this.dtrace.on('exit', function (code) {
	  console.log('child process exited with code ' + code);
	});
}

util.inherits(DtraceConsumer, events.EventEmitter);

exports.DtraceConsumer = DtraceConsumer;

