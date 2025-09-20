## ioctlScan.dll

Run with !ext command

This grabs all running drivers and scans for possible IOCTL calls, this is great for hunting down vulnerablities in drivers.

## wor.exe

Run with the !wor commnd

This is a full object namespace walker

It takes in a first parameter as a object directory path (Ex: \Device) and enumerates all of the entries withing the given directory.

The second "optional" parameter is either a harddisk or a shadowcopy to walk, it also can restore deleted files if your ever in a pinch with the copy command.
