paracode
=============

This is an experiment to use [DTrace](http://en.wikipedia.org/wiki/DTrace) to monitor the user activities. 

Paracode keep track of all relevant website visited during a coding session. So you don't have to take notes of URL or remember the search you did, paracode do this for you.

Each file (.py, .js, .c, .h, .m, erl) is annotated with the recently visited websites. Since it used Dtrace, no plugins is required on your browser.

You can view the history at [http://localhost:3000/](http://localhost:3000/)


Requirements
-----------

- MacOS X
- DTrace
- Nodejs
	- node-async
	- express
	- node-sqlite3

Limitations
-----------
- Https website are not saved
- Only vim and Xcode are supported for now (you can add your own in paracode.d)
	
	 `/execname == "vim" || execname == "Xcode"/`

- It's really experimental


Usage
-----------
`sudo node paracode.js 2> /dev/null &`

`open http://localhost:3000`

License
-----------

###### Paracode ######

Copyright (c) 2012 Gabriel Grise <ggrise at ggri.se>

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.


----------------------------------------------------------

Third-party software license
------------------

###### Bootstrap ######

Copyright 2012 Twitter, Inc.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
