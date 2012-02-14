var sqlite = require('sqlite3'),
	express = require('express'),
	path = require('path'),
	ParaConsumer = require("./lib/pconsumer").ParaConsumer,
	DtraceConsumer = require("./lib/dtrace").DtraceConsumer;


var dtrace = new DtraceConsumer();

if(process.env.SUDO_UID) {
	process.setuid(parseInt(process.env.SUDO_UID));
}

var paraConsumer = new ParaConsumer(dtrace);


var db = new sqlite.Database("codenurl.db");

db.serialize(function() {
	db.run("CREATE TABLE IF NOT EXISTS fileurls (file TEXT, fdate TEXT, fexec TEXT, hdate TEXT, hexec TEXT, host TEXT, path TEXT)");
	db.run("CREATE INDEX IF NOT EXISTS file_idx ON fileurls (file)");
});


paraConsumer.on("capture", function(snapshot) {
		var file = snapshot.file;
		var urls = snapshot.urls;

		db.serialize(function() {
			var stmt = db.prepare("INSERT INTO fileurls VALUES (?,?,?,?,?,?,?)");
			urls.forEach(function(hurl)  {
				if(!hurl.info) return;
				stmt.run(file.info.filename, 
						file.time.getTime(),
						file.execname,
						hurl.time.getTime(),
						hurl.execname,
						hurl.info.host,
						hurl.info.path)
			}); 
			stmt.finalize(); 
		});
});

paraConsumer.start();

var search_files = function(file, callback) {
	  var records = [];
	  db.serialize(function() {
		db.each("SELECT * FROM fileurls where file like ? order by hdate desc", "%"+file, function(err, row) {
			row.basename = path.basename(row.file);
	  		records.push(row);
		}, function(err, count) {
			callback(records);
		});
	});
}

var last_files = function(callback) {
	var files = [];
	db.serialize(function() {
		db.each("select distinct file,max(fdate) as fdate from fileurls group by file order by fdate desc limit 20", function(err, row) {
			row.basename = path.basename(row.file);
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

