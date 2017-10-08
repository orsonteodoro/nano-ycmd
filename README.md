# nano-ycmd
The ycmd code completion support for nano is found in the ymcd-code-completion branch.

![Alt text](csharp-ynano-example.png?raw=true "CSharp IntelliSense with OmniSharp and ycmd.")

#### Branches

* The master branch contains upstreams gnu nano source code untouched.
* The ymcd-code-completion contains a modification to gnu nano that has ycmd support.

#### Which commits are working?  Which one should I clone?

The latest may be broken.

You can use the following which have been tested:
* 011aff80e9b53785c4bac0da6763e37042d7d7eb (recently tested; experimental)
* 1f1a50665877e6dd6f6d09999de3166f4b84a9a2 (recently tested but old; non-simd non-multicore)

#### Dependencies
* ycmd >= commits later than April 17, 2015, with new hmac computation (https://github.com/Valloric/ycmd/commit/426833360adec8db72ed6cef9d7aa7f037e6a5b8)
* >=jedi 0.10, for python support and for completer commands to work.
* Latest jedihttp, for python completion commands support.
* Either nettle, openssl, or "libgcrypt with glib" cryptographic library, to mitigate MITM attack between ycmd and nano text editor
* neon, for http interprocess communication between nano editor and ycmd server
* YCM-Generator (https://github.com/rdnetto/YCM-Generator), for C/C++/Objective-C/Objective-C++ support to generate a .ycm_extra_conf.py
* Bear (https://github.com/rizsotto/Bear), for C/C++/Objective-C/Objective-C++ support to generate a compile_commands.json.
* Clang, for C/C++/Objective-C/Objective-C++ code completion.
* GNU Make, to clean up the project files
* Sed, for patching .ycm_extra_conf.py
* Bash >=4, for `&|` support
* Unix, Linux, Cygwin for /dev/null and /dev/random support
* NXJSON, for server response parsing (A Makefile patch applied to NXJSON package needs to be applied https://github.com/orsonteodoro/oiledmachine-overlay/blob/master/dev-libs/nxjson/files/nxjson-9999.20141019-create-libs.patch so that it is a shared library)
* compdb (https://github.com/Sarcasm/compdb) and Ninja, for Ninja build system support
* jq (https://stedolan.github.io/jq/) (OPTIONAL) is json beautifier and filter.  This is used to clean the DiagnosticResponse after parsing and inject an index on the node to allow for nano-ymcd to conveniently to find a FixIt based on an index selected by the user when the user hovers over this line/index with a shortcut key.  Currently, the `Display All FixIts` is broken because of the non-deterministic bug.
* GNU findutils, requires for the find utility to search for Makefile, configure, *.ninja, *.pro, files.
* GNU coreutils, nano-ycmd needs tac command to reverse the clang system includes order for SIMD headers.
* AVX512, AVX2, SSE2, MMX (OPTIONAL and undergoing testing) for string_replace and escape_json.
* OpenMP (OPTIONAL and undergoing testing) via --with-openmp for multicore string_replace and escape_json.

#### My distribution doesn't have the required dependencies

You can look at my gentoo package overlay https://github.com/orsonteodoro/oiledmachine-overlay to see how to properly compile them or you can research them to build packages for your distribution.

#### What are the new hot keys to use this functionality?

See https://github.com/orsonteodoro/nano-ycmd/blob/ymcd-code-completion/src/global.c#L1389 .

Some of these features require the user to begin to type their code before the menu shows.

#### Why does the completer command "Get Documentation" not work for c-sharp?

Your distribution has not packaged the xml files properly.  Compile nano-ycmd in debug mode and inspect the logs (ynano.txt, jedihttp_*.log, omnisharp_*.log) in the /tmp folder to see which xml documentation files are required.

#### Which completer commands work and how do I access them and what is the expected behavior?

Completer commands add beyond code completion.  It is optional but powerful features for the developer.

The features below are still in development.  Some may be feature complete.

Do Alt-\` to bring up the completer commands menu

To execute a completer command do Ctrl-letter

To exit the completer commands do Ctrl-space

Some completer commands may not work for the particular language that you working with.

Tested and passed | Feature Complete? | Working? | Feature | Description
--- | --- | --- | ------------| -------------------------------------------
Yes | Yes | Yes | GoToInclude | Loads the include file in buffer
Yes | Yes | Yes | GoToDeclaration | Puts the cursor at the variable declaration
Yes | Yes | Yes | GoToDefinition | Puts the cursor at the function definition
No  |  No |  No | GoToDefinitionElseDeclaration | Puts the cursor at the definition first, or it puts it on the declaration if it can't find the definition.
No | No | Yes | GoTo | Should display description in the status bar.  Goes definition or declaration whatever makes sense.
Yes | Maybe | Yes | GoToImprecise | Faster but less accurate version of GoTo but should put the cursor.
No | Yes | Yes | ReloadSolution | Reloads a C# solution
No | No | No | GoToReferences | Lists references
No | Yes | Yes | GoToImplementation | Goes to abstract class
No | No | No | GoToImplementationElseDeclaration | Goes to the implemention first then if it can't find it goes to the declaration
Yes (Procs Randomly/Not deterministic; works for %d->%s format specifier, missing semicolon, identifier spelling errors; tested only in c language) | Maybe (needs more test cases) | Yes | FixIt | Displays trivial changes and fixes chosen ones automatically
Yes | Yes | Yes | GetDoc | Displays documentation in new buffer
No | Yes | Yes | GetDocImprecise | Faster version but less accurate version of GetDoc.
No | Yes | No (Subserver problems) | RefactorRename | Renames a symbol in every file in the project
Yes | Yes | Yes | GetType | Returns the type of a variable or return the function signature.
Yes | Yes | Yes | GetTypeImprecise | Faster but less accurate version of GetType
No | Yes | Yes | RestartServer | Reloads the subserver
No | Yes | Yes | GoToType | Goes to a type
No | Yes | Yes | ClearCompilationFlagCache | Clears and updates FlagsForFile from .ycm_extra_conf.py
Yes | Yes | Yes | GetParent | Gets parent class or method
No | No | No | SolutionFile | Gets the path to the solution file

#### Why use ycmd backend over the builtin WORDCOMPLETION?

ycmd allows to you use IntelliSense for C# sources using omnisharp-server/omnisharp-roslyn that the big IDE editors have.  It goes beyond word completion providing documentation about method signatures and real time syntax checking (currently not supported in nano-ycmd).

#### How do I use this code completion feature?

Just type and press CTRL-LETTER.  Use Ctrl-space to exit the code completion selections.

#### What languages supported?
python, javascript*, typescript, rust, go, C*, C++*, Objective-C*, Objective-C++*, C#*


Working with some of these languages require additional requirements:

*JavaScript support requires both .tern-project and .tern-config project file to work.

*C# support requires a .sln project file to work.

*C, C++, Objective-C, Objective-C++ requires either a *.pro, configure, CMakeList.txt, GNUmakefile, Makefile, or makefile to work.  An optional *.ninja file may be supplied in your project and would require additional steps to handle.

#### Why does the autocompleter not work with C, C++, Objective C, Objective C++ with a single hello world file?

You may forgot to have a Makefile, makefile GNUmakefile for make, *.pro for qmake, configure for autotools, CMakeLists.txt for cmake or forgot to set the YCMG_PROJECT_PATH to point to your top level project folder.  nano-ycmd will pass it to bear and YCM-Generator to properly create a .ycm_extra_conf.py and compile_commands.json.  The compile_commands.json is for clang compliation database system (http://clang.llvm.org/docs/JSONCompilationDatabase.html).  .ycm_extra_conf.py contains headers and constants that are per project.

#### The completer commands doesn't work for C, C++, Objective C, Objective C++

Try deleting the compile_commands.json file and .ycm_extra_conf.py in the current (working) directory.  Those files should be only in the directory mentioned in the YCMG_PROJECT_PATH environmental variable passed into nano-ycmd.

#### Why is my intellisense not working with my C#?
You didn't set up ycmd correctly.  It needs to see a sln file or maybe project.json file if json is supported in ycmd.

#### Why is the master branch old?
I don't have an update bot yet.

#### Why is this not a plugin?
I don't see any plugin support in nano.

#### What do i need to pass to configure?

Your setup may vary depending on if your distro patched ycmd.  In my case, I modified ycmd to use absolute paths.  The vanilla ycmd uses relative path to the thirdparty folder.

#### You need a crypto library.  Choose one of either:

--with-openssl

or

--with-nettle

or

--with-libgcrypt

#### You need to enable ycmd support

--enable-ycmd

#### You need to set up environmental variables to pass to the configure script:

(IMPORTANT) The python version must be the same as the compiled ycmd scripts.

YCMD_PATH="/usr/lib64/python3.4/site-packages/ycmd"
PYTHON_PATH="/usr/bin/python3.4" 

#### The following are optional environmental variables to pass to the configure script pass empty "" if you don't want support:

#### for rust language:

RACERD_PATH="/usr/bin/racerd" 

RUST_SRC_PATH="/usr/share/rust/src" 

#### for go language:

GODEF_PATH="/usr/bin/godef" 

GOCODE_PATH="/usr/bin/gocode" 

#### for C / C++ / Objective-C / Objective-C++ language:

YCMG_PATH="/usr/bin/config_gen.py"

#### What would the resulting string look like to configure ycmd for the autotools build system?

./autogen.sh

CFLAGS="-g" YCMG_PATH="/usr/bin/config_gen.py" PYTHON_PATH="/usr/bin/python3.4" RACERD_PATH="/usr/bin/racerd" RUST_SRC_PATH="/usr/share/rust/src" GODEF_PATH="/usr/bin/godef" GOCODE_PATH="/usr/bin/gocode" YCMD_PATH="/usr/lib64/python3.4/site-packages/ycmd" ./configure --enable-ycmd --with-openssl
make

The -g adds debugging information for developers for the gdb debugger but not needed for regular users. 

#### YCM-Generator
The following environmental variables are defined by nano-ycmd are required for C family support (C/C++/ObjC/ObjC++):

* YCMG_PROJECT_PATH - This should point to the folder containing the top-level Makefile, configure, CMakeList.txt. (REQUIRED)
* YCMG_FLAGS - This adds extra parameters to config_gen.py.  I recommend using make over autotools specifically `-b make` because more include files are exposed instead of allowing YCM-Generator autodetect.  This environment variable is optional but recommended be in use in certain situations.

So to use it in combination of nano-ycmd (ynano) without Ninja, it would look like:

`YCMG_FLAGS="-b make" YCMG_PROJECT_PATH="/var/tmp/portage/app-editors/nano-ycmd-9999.20170201/work/nano-ycmd-7611e4eb827980da1057f6768d00bd322fa1c58f" ynano ycmd.c`

Also, if you add new libraries or files, you should delete both the .ycm_extra_conf.py and compile_commands.json so that nano-ycmd can regenerate them.

Also, if you change languages between C, C++, Objective-C, Objective-C++ because your project uses multiple languages, you should regenerate them when using them because it will produce new header include lists for that particular language.  Currently no hotkey exist to delete and regenerate those files.  nano-ycmd automatically skips generation to save time if they already exist.

#### Ninja + YCM-Generator together

We need the YCMG_PROJECT_PATH above plus the two required environment variables below:

* NINJA_BUILD_PATH - This should point to the folder containing your *.ninja file (REQUIRED)
* NINJA_BUILD_TARGETS - This should be the rule(s) space seperated and listed under the `# Rules for compiling comment` section and having the line begin with `command = clang` or whatever compiler you are using. (REQUIRED)

For NINJA_BUILD_TARGETS, the contents of gst-transcoder's build.ninja is presented below:

```
# This is the build file for project "gst-renderer"
# It is autogenerated by the Meson build system.
# Do not edit by hand.

ninja_required_version = 1.5.1

# Rules for compiling.

rule c_COMPILER
 command = clang  $ARGS '-MMD' '-MQ' $out '-MF' '$DEPFILE' -o $out -c $in
 deps = gcc
 depfile = $DEPFILE
 description = Compiling c object $out

rule c_PCH
 command = clang  $ARGS '-MMD' '-MQ' $out '-MF' '$DEPFILE' -o $out -c $in
 deps = gcc
 depfile = $DEPFILE
 description = Precompiling header $in


# Rules for linking.

rule STATIC_LINKER
 command = ar $LINK_ARGS $out $in
 description = Static linking library $out
```

NINJA_BUILD_TARGETS can only be c_COMPILER and/or c_PCH but not STATIC_LINKER.  Also it only works if your project is using both YCMG_PROJECT_PATH and NINJA_BUILD_TARGETS for Ninja support.

In the above example, we have a Makefile and a configure.  We override the YCM-Generator autodetection because the .ycm_extra_conf.py contains more headers with the Makefile preference over the autodetected configure with first come first serve priority.

For Ninja + Other build system, it should look like:

`NINJA_BUILD_PATH="/var/tmp/portage/media-plugins/gst-transcoder-1.8.2-r1/work/gst-transcoder-1.8.2/mesonbuild" NINJA_BUILD_TARGETS="c_COMPILER" YCMG_PROJECT_PATH="/var/tmp/portage/media-plugins/gst-transcoder-1.8.2-r1/work/gst-transcoder-1.8.2" ynano gst/transcode/gst-cpu-throttling-clock.c 2>out.txt`

In the above example there is only a configure script in /var/tmp/portage/media-plugins/gst-transcoder-1.8.2-r1/work/gst-transcoder-1.8.2 folder and is autodetected by YCM-Generator.  A build.ninja file is located in /var/tmp/portage/media-plugins/gst-transcoder-1.8.2-r1/work/gst-transcoder-1.8.2/mesonbuild folder.

#### Why does the user experience suck?
We are working on that.  Feel free to merge your changes.

#### Why does it do only word matching within a single source code?
The example reference script used it that way.

#### Quality?  Is it finished or complete?

Code completion as in looking outside of the current opened buffers in nano is feature complete but the entire feature set of the completer commands is not feature complete.  The UX could also be improved.

#### What license is GNU nano released under?

GPL version 3 or newer

#### What license is nano-ycmd feature set released under?

It is GPL version 3 or newer

#### What could I do to help?

Add better user interface or user interaction.  Emacs-ycmd is a good example.

Fix bugs or improve the speed.  Solve why clang/llvm 3.9.1 doesn't show FixIts 100% of the time as expected.

#### When will it be considered ready for review to be included in the official GNU nano?

After the UX has been polished and all the features are feature complete.  If they do not want to include this patchset, we will fork nano.  I want this merged eventually if possible or someone do it if I am gone or no longer working on it.

#### Can I install both vanilla nano and nano-ycmd along side each other?

Yes you can, but you need to change the src/Makefile.am.  Rerun autogen.sh.  Do configure again specifying features then make.  Just keep the binary only.  I recommend installing both since nano-ycmd is still a work in progress.

#### What is up with the debug spew?

If you compiled nano-ycmd with --enable-debug then you can redirect the stderr to a file to inspect it later.  You should use --disable-debug if you are not a developer.

For example:
nano 2>/tmp/out.txt

#### Special thanks goes to...

marchelzo and twkm from freenode ##C channel for the clear excess stdin fix.

Also see --version or https://github.com/orsonteodoro/nano-ycmd/blob/052b4866f3b24caeed877ae6f017f422d1443ed9/src/nano.c#L929 for other credits

#### How do I add changes?
1. Click fork at the top of this page to create a repository on your account
2. git clone https://github.com/orsonteodoro/nano-ycmd.git
3. cd into folder
4. git checkout -b myfeaturename
5. make changes
6. git commit -m "My description here"
7. git push -u origin myfeaturename
8. go to your repository
9. make pull request
