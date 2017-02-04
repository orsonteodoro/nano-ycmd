# nano-ycmd
The ycmd code completion support for nano is found in the ymcd-code-completion branch.

![Alt text](csharp-ynano-example.png?raw=true "CSharp IntelliSense with OmniSharp and ycmd.")

####Branches

* The master branch contains upstreams gnu nano source code untouched.
* The ymcd-code-completion contains a modification to gnu nano that has ycmd support.

####Which commits are working?  Which one should I clone?

The latest may be broken.

You can use the following which have been tested:
* 1b992e315f763460fcb64b76dbf9d63ff4cede87 (recently tested)

####Dependencies
* ycmd >= commits later than year 2015, with new hmac computation
* nettle or "openssl and glib" cryptographic library, to mitigate MITM attack between ycmd and nano text editor
* neon, for http interprocess communication between nano editor and ycmd server
* YCM-Generator (https://github.com/rdnetto/YCM-Generator), for C/C++/Objective-C/Objective-C++ support to generate a .ycm_extra_conf.py
* Bear (https://github.com/rizsotto/Bear), for C/C++/Objective-C/Objective-C++ support to generate a compile_commands.json.
* Clang, for C/C++/Objective-C/Objective-C++ code completion.
* GNU Make, to clean up the project files
* Sed, for patching .ycm_extra_conf.py
* Bash >=4, for `&|` support
* Unix, Linux, Cygwin for /dev/null and /dev/random support

####My distribution doesn't have the required dependencies

You can look at my gentoo package overlay https://github.com/orsonteodoro/oiledmachine-overlay to see how to properly compile them or you can research them to build packages for your distribution.

####Why use ycmd backend over the builtin WORDCOMPLETION?

ycmd allows to you use IntelliSense for C# sources using omnisharp/omnisharp-roslyn that the big IDE editors have.  It goes beyond word completion.

####How do I use this code completion feature?

Just type and press CTRL-LETTER.  Use CTRL-X to exit the code completion selections.

####What languages supported?
python, javascript, typescript, rust, go, C, C++, Objective C, Objective C++

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

######The following are optional environmental variables to pass to the configure script pass empty "" if you don't want support:

######for rust language:
RACERD_PATH="/usr/bin/racerd" 
RUST_SRC_PATH="/usr/share/rust/src" 

######for go language:
GODEF_PATH="/usr/bin/godef" 
GOCODE_PATH="/usr/bin/gocode" 

######for C / C++ / Objective-C / Objective-C++ language:
YCMG_PATH="/usr/bin/config_gen.py"

######How would the result string look like?

./autogen.sh
CFLAGS="-g" YCMG_PATH="/usr/bin/config_gen.py" PYTHON_PATH="/usr/bin/python3.4" RACERD_PATH="/usr/bin/racerd" RUST_SRC_PATH="/usr/share/rust/src" GODEF_PATH="/usr/bin/godef" GOCODE_PATH="/usr/bin/gocode" YCMD_PATH="/usr/lib64/python3.4/site-packages/ycmd" ./configure --enable-ycmd --with-openssl
make

The -g adds debugging information for developers but not needed for regular users. 

######YCM-Generator support
The following environmental variables are defined when running nano-ycmd:

* YCMG_PROJECT_PATH - This should point to the folder containing the top-level Makefile, configure, CMakeList.txt, 
* YCMG_FLAGS - This adds extra parameters to config_gen.py.  I recommend using make over autotools specifically `-b make` because more include files are exposed instead of allowing YCM-Generator autodetect.

So to use it in combination of nano-ycmd (ynano), it would look like:

YCMG_FLAGS="-b make" YCMG_PROJECT_PATH="/var/tmp/portage/app-editors/nano-ycmd-9999.20170201/work/nano-ycmd-7611e4eb827980da1057f6768d00bd322fa1c58f" ynano ycmd.c

Also, if you add new libraries or files, you should delete both the .ycm_extra_conf.py and compile_commands.json so that nano-ycmd can regenerate them.

Also, if you change languages, between C, C++, Objective-C, Objective-C++, you should regenerate them.  Currently no hotkey exist to delete and regenerate those files.  nano-ycmd automatically skips generation to save time if they already exist.

######Why does the user experience suck?
We are working on that.  Feel free to merge your changes.

######Why does it do only word matching within a single source code?
The example reference script used it that way.

######Quality?  Is it finished or complete?

Nah, I just have it working.  The UX could be improved.

######What license is GNU nano released under?

GPL version 3

######What license is nano-ycmd feature set released under?

It is GPL version 3.

######What other dependencies were involved?

NXJSON which is released under GPL 3 by Yaroslav Stavnichiy.

####How long did it take to make this?

About 2-3 days.

####What could I do to help?

Add better user interface or user interaction.  Emacs-ycmd is a good example.

#####When will it be considered ready for review to be included in the official GNU nano?

After the UX has been polished.

#####Can I install both vanilla nano and nano-ycmd along side each other?

Yes you can, but you need to change the src/Makefile.am.  Rerun autogen.sh.  Do configure again specifying features then make.  Just keep the binary only.  I recommend installing both since nano-ycmd is still a work in progress.

#####What is up with the debug spew?

If you compiled nano-ycmd with --enable-debug then you can redirect the stderr to a file to inspect it later.  You should use --disable-debug if you are not a developer.

For example:
nano 2>/tmp/out.txt

####Special thanks goes to....

marchelzo and twkm from freenode ##C channel for the clear excess stdin fix.

####How do I add changes?
1. Create a repository on your account
2. git clone https://github.com/orsonteodoro/nano-ycmd.git
3. cd into folder
4. git checkout -b myfeaturename
5. make changes
6. git commit -m "My description here"
7. git push -u origin myfeaturename
8. go to your repository
9. make pull request
