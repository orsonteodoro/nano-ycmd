# nano
Unofficial mirror of GNU nano.  The ycmd code completion support for nano is found in the ymcd-code-completion branch.

####Name of the feature set?

ycmd-nano

####Branches

The master branch contains the official nano source code.
The ymcd-code-completion contains a modification to nano to have ycmd support?

####Dependencies
ycmd >= commits later than year 2015, with new hmac computation
nettle or "openssl and glib" cryptographic library, to mitigate MITM attack between ycmd and nano text editor
neon, for http interprocess communication between nano editor and ycmd server

####Why use ycmd backend over the builtin WORDCOMPLETION?

ycmd allows to you use IntelliSense for C# sources using omnisharp/omnisharp-roslyn that the big IDE editors have.  It goes beyond word completion.

####How do I use this code completion feature?

Just type and press CTRL-<LETTER>.  Use CTRL-X to exit the code completion selections.

####What languages supported?
python, javascript, typescript, rust, go

####What languages are currently not supported?
C, C++, Objective C, Objective C++

####Will you add C family languages support?
It depends if I have time.  We need to intergrate YCM-Generator.

####Why is my intellisense not working with my C#?
You didn't set up ycmd correctly.  It needs to see a sln file or project.json file.

####Why is the master branch old?
I don't have an update bot yet.

####Why is this not a plugin?
I don't see any plugin support in nano.

####What do i need to pass to configure?

Your setup may vary depending on if your distro patched ycmd.  In my case, I modified ycmd to use absolute paths.  The vanilla ycmd uses relative path to the thirdparty folder.

######You need a crypto library.  Choose either:
--with-openssl
or
--with-nettle

######You need to enable ycmd support
--enable-ycmd

######You need to set up environmental variables to pass to the configure script:
(IMPORTANT) The python version must be the same as the compiled ycmd scripts.

YCMD_PATH="/usr/lib64/python3.4/site-packages/ycmd"
PYTHON_PATH="/usr/bin/python3.4" 

######The following are optional environmental variables to pass to the configure script:
for rust language:
RACERD_PATH="/usr/bin/racerd" 
RUST_SRC_PATH="/usr/share/rust/src" 

######for go language:
GODEF_PATH="/usr/bin/godef" 
GOCODE_PATH="/usr/bin/gocode" 

######How would the result string look like?

./autogen.sh
CFLAGS="-g" PYTHON_PATH="/usr/bin/python3.4" RACERD_PATH="/usr/bin/racerd" RUST_SRC_PATH="/usr/share/rust/src" GODEF_PATH="/usr/bin/godef" GOCODE_PATH="/usr/bin/gocode" YCMD_PATH="/usr/lib64/python3.4/site-packages/ycmd" ./configure --enable-ycmd --with-openssl
make

The -g adds debugging information for developers but not needed for regular users. 

######How do I run nano with libstring_replace.so?

LD_LIBRARY_PATH="../third_party/pixelbeat.org"  ./nano hello.cs

or place the libstring_replace.so found in the third_party/pixelbeat.org in your /usr/lib folder and just run nano.

Remember that libstring_replace.so is licensed under LGPL (any version).

######Why does the user experience suck?
We are working on that.  Feel free to merge your changes.

######Why does it do only word matching within a single source code?
The example reference script used it that way.

######Quality?  Is it finished or complete?

Nah, I just have it working.  The UX could be improved.

######What license is GNU nano released under?

GPL version 3

######What license is ycmd-nano feature set released under?

It is GPL version 3.

######What other dependencies were involved?

NXJSON which is released under GPL 3 by Yaroslav Stavnichiy.  Eventually compiled in the nano executible.
string_replace was released under LGPL by Pádraig Brady.  It is a seperate library because of licensing.  It maybe replaced with your own or you include this one.

####Why do we depend on the string_replace library provided by https://github.com/pixelb/libs?

No good offerings with license compatiblity with GPL3 for a string_replace in C.  You may use replacement of string_replace but keep the function signature the same.  You may commit a replacement for string_replace that is GPL3 if you want.  I tested glib and it doesn't work.  string_replace by brady turned out to be robust.

####How long did it take to make this?

About 2-3 days.

####What could I do to help?

Add better user interface or user interaction.  Emacs-ycmd is a good example.

####How do I add changes?
1. Create a repository on your account
2. git clone https://github.com/orsonteodoro/nano.git
3. cd into folder
4. git checkout -b myfeaturename
5. make changes
6. git commit -m "My description here"
7. git push -u origin myfeaturename
8. go to your repository
9. make pull request
