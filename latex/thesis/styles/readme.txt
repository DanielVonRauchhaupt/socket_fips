FILES

We created our own LaTeX-Classes in order to provide a common thesis layout.

cs-*
  Uni Potsdam
  Institut für Informatik

    - cs-thesis: inherits from scrreprt and extends it with 
                 some generic macros
    - cs-slides: inherits from beamer and extends it with 
                 some generic macros
    - cs-common: contains packages and macros used by 
                 cs-thesis and cs-slides
    
bsvs-*
  Operating Systems and Distributed Systems (BSVS)
  
    - bsvs-thesis: inherits from cs-thesis and extends it with 
                   bsvs specific macros
    - bsvs-slides: inherits from cs-slides and extends it with 
                   bsvs specific macros
    - bsvs-common: contains bsvs specific packages and macros used by 
                   bsvs-thesis and bsvs slides

CLASS DIAGRAM

 +-------------+                                       +-------------+
 |  scrreprt   |                                       |   beamer    |
 |(KOMA-Script)|                                       |             |
 +-------------+                                       +-------------+
        ^                                                     ^
       / \                                                   / \
       -+-                                                   -+-
        |                                                     |
        |                                                     |
        |                                                     |
 +-------------+            +-------------+            +-------------+
 |  cs-thesis  | /\_________|  cs-common  |_________/\ |  cs-slides  |
 |             | \/         |             |         \/ |             |
 +-------------+            +-------------+            +-------------+
        ^                                                     ^
       / \                                                   / \
       -+-                                                   -+-
        |                                                     |
        |                                                     |
        |                                                     |
 +-------------+            +-------------+            +-------------+
 | bsvs-thesis | /\_________| bsvs-common |_________/\ | bsvs-slides |
 |             | \/         |             |         \/ |             |
 +-------------+            +-------------+            +-------------+
 
REFERENCES

Some comments are related to the Beamer documentation. 
In detail, this is the (english) documentation:
 	User Guide to the Beamer Class, Version 3.07
	    http://latex-beamer.sourceforge.net
		        Till Tantau
		tantau@users.sourceforge.net
		       March 11, 2007
 It can be downloaded via the internet using the URL:
     ftp://ftp.ctan.org/tex-archive/macros/latex/contrib/↵
     beamer/doc/beameruserguide.pdf
The reference to this documentation is named 'Beamer-Doc'.

Some comments are related to the KOMA-Script documentation. 
In detail, this is the (german) documentation:
              Die Anleitung
               KOMA-Script
    Markus Kohm    Jens-Uwe-Morawski
               2007-09-17
It can be downloaded via the internet using the URL:
    ftp://ftp.ctan.org/tex-archive/macros/latex/contrib/↵
    koma-script/scrguide.pdf
The reference to this documentation is named 'KOMA-Doc'.

The name 'LaTeX-Book' indicates:
                          Frank Mittelbach
                          Michel Goossens
                          Der LaTeX Begleiter
    2., überarbeitete und erweiterte Auflage
This book (and some more stuff about LaTeX) can be borrowed in my
(Stefan's) office, room 2.21.

Some of the necessary information can be found
in LaTeX-Book (Ch.A.4). Furthermore, the following documentation
gave a lot of information about writing classes and packages:
    LaTeX2ε for class and package writers
         1995–1998 The LaTeX3 Project
It can be downloaded via the internet using the URL:
    http://www.latex-project.org/guides/clsguide.pdf
The reference to this documentation is named 'CPWriters'.
