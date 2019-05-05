
Debian
====================
This directory contains files used to package digiquiand/digiquian-qt
for Debian-based Linux systems. If you compile digiquiand/digiquian-qt yourself, there are some useful files here.

## digiquian: URI support ##


digiquian-qt.desktop  (Gnome / Open Desktop)
To install:

	sudo desktop-file-install digiquian-qt.desktop
	sudo update-desktop-database

If you build yourself, you will either need to modify the paths in
the .desktop file or copy or symlink your digiquian-qt binary to `/usr/bin`
and the `../../share/pixmaps/digiquian128.png` to `/usr/share/pixmaps`

digiquian-qt.protocol (KDE)

