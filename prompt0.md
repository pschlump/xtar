This is a Go project to create a series of CLI tools to replace tar, cpio, zip, unzip, 7z.
The goal is a single binary that uses argv[0] to differentiate its set of command line flags and
replace all of these with a single tool.  The library ../pluto has modules for all of the different
compression schemes.  Beyond just being a replacement the command should be able to notice the
different file extensions and work with them.

So...

    tar -xf myfile.zip

Should work to extract all of the file sin the .zip archive without having to go to the unzip command.
Analyze the different command line utilities and figure out the appropriate cross tool behaviors for
different file types.

Document it clearly in a README.
