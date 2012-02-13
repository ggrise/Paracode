var http = require('http'),
	async = require('async'),
	sqlite = require('sqlite3'),
	express = require('express'),
	url = require('url'),
	DtraceConsumer = require("./lib/dtrace").DtraceConsumer;


var consumer = new DtraceConsumer();

if(process.env.SUDO_UID) {
	process.setuid(parseInt(process.env.SUDO_UID));
}

var db = new sqlite.Database("codenurl.db");

db.serialize(function() {
	db.run("CREATE TABLE IF NOT EXISTS fileurls (file TEXT, fdate TEXT, fexec TEXT, hdate TEXT, hexec TEXT, host TEXT, path TEXT)");
	db.run("CREATE INDEX IF NOT EXISTS file_idx ON fileurls (file)");
});
var last_url = [];

var eviction = function() {
	to_evince = [];
	var curtime = new Date().getTime();
	for(var k in last_url) {
		if(curtime - last_url[k].time.getTime() > 1000*60*5) {
				to_evince.push(k);
		}
	}
	to_evince.forEach(function(k) { delete last_url[k]; })
};

consumer.on("http", function(data) {
	var info = data.info;
	var hurl = url.parse("http://" +  info.host + info.path);
	
	if(hurl.pathname.match(/^.*[.\/](jpe?g|ico|woff|png|gif|swf|bmp|avi|flv|js(on)?|xml|css|login\.php)\/?$/i) || hurl.pathname.match(/\/(ads|js|cgi-bin|collect)\//i)) {
		return;
	}
	if(hurl.hostname.match(/^(..?|[0-9]|[^.]+\.gstatic|[^.]+\.gravatar|www\.facebook|assets|log|ocsp|pageads|static|api|safebrowsing(-[^.]+)?|pixel|maps|cdn)[0-9]*\./i) || hurl.hostname == "localhost" || hurl.hostname == "127.0.0.1") {
		return;
	}

	if(last_url[info.referer]) {
		//if the host name is the same and the time is < 2sec ignore the page
		var ref = last_url[info.referer];
		if(data.time.getTime() - ref.time.getTime() < 3000) {
			data.info = null;
		}
	} 
	last_url[hurl.href] = data;
	eviction();
});

consumer.on("file", function(data) {
	eviction();
	var _urls = [];
	for( var k in last_url)  {
		_urls.push(last_url[k]);
	}
	last_url = {};
	filter_content_type("text/html", _urls, function(urls) {
		db.serialize(function() {
			var stmt = db.prepare("INSERT INTO fileurls VALUES (?,?,?,?,?,?,?)");
			urls.forEach(function(hurl)  {
				if(!hurl.info) return;
				stmt.run(data.info.filename, 
						data.time.getTime(),
						data.execname,
						hurl.time.getTime(),
						hurl.execname,
						hurl.info.host,
						hurl.info.path)
			}); 
			stmt.finalize(); 
		});
	});
});
var filter_content_type = function(content_type, list, mcallback) {

	var reqlist = [];

	list.forEach(function(data) {
		var info = data.info;
		if(!info) return;

		var host = info.host.split(":");
		var port = host.length > 1 ? parseInt(host[1]) : 80;
		
		reqlist.push(function(callback) {

			var client = http.createClient(port, host[0]);
			var req = client.request("HEAD", info.path, {host:info.host});
			req.on('response', function(res) {
				if(res.statusCode	< 399) {
					var ct = res.headers['content-type'];
					if(ct && ct.indexOf(content_type) != -1) {
						//good!
						callback(null, data);
						return;
					}
				}
				callback(null, false);
			});
			req.end();
		});
	});
	
	async.parallel(reqlist, function(err, results){
		var res = [];
		results.forEach(function(v) { if(v) res.push(v); });
		mcallback(res);
	});
}
var search_files = function(file, callback) {
	  var records = [];
	  db.serialize(function() {
		db.each("SELECT * FROM fileurls where file like ? order by hdate desc", "%"+file, function(err, row) {
	  		records.push(row);
		}, function(err, count) {
			callback(records);
		});
	});
}

var last_files = function(callback) {
	var files = [];
	db.serialize(function() {
		db.each("select distinct file,max(fdate) as fdate from fileurls order by fdate desc limit 20", function(err, row) {
			files.push(row);
		}, function(err, count) {
			callback(files);
		})
	})
}
var app = express.createServer();
app.configure(function(){ 
	app.set('view engine', 'ejs');
	app.use(express.static(__dirname + '/static')); 
});
app.get('/', function(req, res){
		if(req.query.q) {
			search_files(req.query.q, function(recs) {
				res.render('index.ejs',{records:recs, topfiles:false});	
			});
		} else {
			last_files(function(files) {
				res.render('index.ejs',{records:false, topfiles:files});	
			});
		}
});

app.listen(3000);

