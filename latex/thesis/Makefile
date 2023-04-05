#
# $Id: Makefile 2746 2008-09-17 13:41:16Z jozinke $
#

# define useful variables, change these if necessary
THESIS   = Bachelorarbeit_Raatschen
BIB      = literature.bib

# define paths to the required programs
BIBTEX   = bibtex
DVIPS    = dvips
LATEX    = latex
MAKEIDX  = makeindex
PDFLATEX = pdflatex
SED      = sed
GAWK     = gawk
GREP     = grep
TOUCH    = touch
GS       = gs
EPSTOPDF = epstopdf
CONVERT  = convert
FIG2DEV  = fig2dev
PLOT     = gnuplot
INKSCAPE = inkscape

# define output as /dev/null to suppress all program output
OUT      = /dev/null

# required programs (as listing for make progs)
REQUIRED = $(BIBTEX) $(CONVERT) $(DVIPS) $(EPSTOPDF) $(FIG2DEV) $(PLOT) $(GS) $(LATEX) $(MAKEIDX) $(PDFLATEX)

# define additional directories
# - bitmap or vector graphics as jpg, png, pdf, fig or svg in /images
# - gnuplot files as plt in /plots
# - local sty files in /styles
IMGDIR   = ./images
PLTDIR   = ./plots
STYDIR   = ./styles

# export style directory
export TEXINPUTS=$(STYDIR):

# defining sourcefiles and other latex-stuff (better not touch anything but texfiles, like for additional include directories)
TEXFILES = $(wildcard *.tex)
STYFILES = $(wildcard $(STYDIR)/*.sty)
TEXSTY = $(TEXFILES) $(STYFILES)
CLASS = $(addsuffix .cls,$(shell sed -n -e '/\\documentclass/,/}/p' $(THESIS).tex | tr -d '\r' | tr -d '\t' | sed -r 's/%.*//;s/ //g' | tr -d '\n' | sed -r 's/.*\{//;s/\}//'))
PACKAGES = $(filter-out $(STYFILES),$(addsuffix .sty,$(shell for p in $(TEXSTY) ; do grep -i -s '[^% ].*usepackage\|RequirePackage' $$p | sed 's/.*usepackage.*{\([^}]*\).*/\1/;s/.*[Rr]equire[Pp]ackage.*{\([^}]*\).*/\1/' ; done | sort | uniq)))

# get all graphics files that are supported in some way or another
PDFIMGS = $(wildcard $(IMGDIR)/*.pdf)
EPSIMGS = $(wildcard $(IMGDIR)/*.eps)
JPGIMGS = $(wildcard $(IMGDIR)/*.jpg)
PNGIMGS = $(wildcard $(IMGDIR)/*.png)
FIGIMGS = $(wildcard $(IMGDIR)/*.fig)
EPSIMGS = $(wildcard $(IMGDIR)/*.eps)
PDFIMGS = $(wildcard $(IMGDIR)/*.pdf)
SVGIMGS = $(wildcard $(IMGDIR)/*.svg)
PLOTS   = $(wildcard $(PLTDIR)/*.plt)

#======================================================================
# no editing below here should be necessary

# get all files that need to be converted into eps
# only include those files that do not have a corresponding file in eps or pdf
# to avoid circular dependencies
EPSFROMPDF = $(filter-out $(EPSIMGS),$(patsubst %.pdf,%.eps,${PDFIMGS}))
PDFFROMEPS = $(filter-out $(PDFIMGS) $(patsubst %.jpg,%.pdf,${JPGIMGS}) $(patsubst %.png,%.pdf,${PNGIMGS}), $(patsubst %.eps,%.pdf,${EPSIMGS}))
EPSFROMJPG = $(filter-out $(EPSIMGS),$(patsubst %.jpg,%.eps,${JPGIMGS}))
EPSFROMPNG = $(patsubst %.png,%.eps,${PNGIMGS})
EPSFROMFIG = $(patsubst %.fig,%.eps,${FIGIMGS})
PDFFROMFIG = $(patsubst %.fig,%.pdf,${FIGIMGS})
EPSFROMSVG = $(filter-out $(EPSIMGS),$(patsubst %.svg,%.eps, ${SVGIMGS}))
PDFFROMSVG = $(filter-out $(PDFIMGS),$(patsubst %.svg,%.pdf, ${SVGIMGS}))
EPSFROMPLT = $(patsubst %.plt,%.eps,${PLOTS})
PDFFROMPLT = $(patsubst %.plt,%.pdf,${PLOTS})

# logfile messages to grep for
RERUN    = "^LaTeX Warning: .* Rerun to get"
WARNING  = "^LaTeX Warning: "
NOFILE   = "^No file "
OVERFULL = "^Overfull "
UNDERFULL= "^Underfull "
ERROR    = "^! "

# first make target: a syntax help to be shown when calling make without params
help:
	@echo " Makefile for compiling to DVI, PostScript and PDF"
	@echo ""
	@echo " Possible targets:"
	@echo "   make dvi      -- creates DVI output"
	@echo "   make ps       -- creates PS file from DVI output"
	@echo "   make pdf      -- uses pdflatex to create PDF"
	@echo "   make images   -- convert everything in /images to useful formats"
	@echo "   make plots    -- converts all Gnuplot plt to images"
	@echo "   make clean    -- deletes all intermediate files"
	@echo "   make mrproper -- deletes everything but the source files"
	@echo ""
	@echo "   make verbose  -- just calls latex (for debugging purposes)"
	@echo "   make check    -- calls latex and shows only warnings and errors"
	@echo "   make progs    -- checks whether all required programs are present"
	@echo "   make show-pkg -- shows which LaTeX packages are included via \usepackage"
	@echo "   make chk-pkg  -- checks whether necessary .sty files are available"
	@echo " Get more help by adding -help to make target, e.g. make pdf-help"

# additional help-targets
dvi-help:
	@echo "  Help for 'make dvi'"
	@echo "  'make dvi' sets the document and produces output in DVI format. The necessary"
	@echo "  calls to BibTeX and Makeindex are all managed automatically. If images in a"
	@echo "  non-usable format are found in the subdirectory '/images', a conversion is done. Same"
	@echo "  goes for Gnuplot scripts in '/plots'."
	@echo ""
	@echo "  Related help topics: images-help, plots-help"

ps-help:
	@echo " Help for 'make ps'"
	@echo " 'make ps' typesets the document as DVI and converts the resulting file into PS"
	@echo " using dvips."
	@echo ""
	@echo " Related help topics: dvi-help"

pdf-help:
	@echo " Help for 'make pdf'"
	@echo " 'make pdf' works in the same way as 'make dvi', but uses pdflatex to produce"
	@echo " PDF output."
	@echo ""
	@echo " Related help topics: dvi-help"

images-help:
	@echo " Help for 'make images'"
	@echo " 'make images' goes through the subdirectory defined as IMGDIR and looks for"
	@echo " all files in the formats EPS, JPG, PNG, PDF, FIG and SVG. The following conversions"
	@echo " are done: EPS -> PDF, JPG -> EPS, PNG -> EPS, PDF -> EPS"
	@echo " Only source files that do not have an equivalent in the destination format"
	@echo " are converted."
	@echo " Programs used for conversion:"
	@echo "   EPS->PDF: epstopdf"
	@echo "   JPG->EPS, PNG->EPS: convert (ImageMagick)"
	@echo "   PDF->EPS: gs (GhostScript)"
	@echo "   FIG->EPS, FIG->PDF: fig2dev (transfig package)"
	@echo "   SVG->EPS: inkscape
	@echo "   SVG->EPS->PDF: epstopdf"

plots-help:
	@echo " Help for 'make plots'"
	@echo " 'make plots' goes through the subdirectory defined as PLOTS and looks for"
	@echo " Gnuplot skript files ending on PLT. These files are plotted and exported"
	@echo " to EPS and PDF."
	@echo " Important note: The PLT file must not set any terminal or output, otherwise"
	@echo " the export will fail!"

clean-help:
	@echo " Help for 'make clean'"
	@echo " 'make clean' removes all files that are created as intermediate results by"
	@echo " latex, bibtex and makeindex."
	@echo " Converted images and plots are not touched."

mrproper-help:
	@echo " Help for 'make mrproper'"
	@echo " 'make mrproper' calls 'make clean' and additionally removes the DVI, PS and"
	@echo " PDF result files. No other files or subdirectories are touched."
	@echo ""
	@echo " Related help topics: clean-help"

verbose-help:
	@echo " Help for 'make verbose'"
	@echo " 'make verbose' just calls latex to process the document.
	@echo " This make target is mainly intended for debugging."
	@echo ""
	@echo " Related help topics: check-help"

check-help:
	@echo " Help for 'make check'"
	@echo " 'make check' is intended for debugging purposes. It calls latex to process"
	@echo " the document. After processing the document, the logfile is checked for"
	@echo " errors, warnings, missing files and over/underfull boxes. Only these log"
	@echo " messages are displayed."
	@echo " If an error is found, 'make verbose' could by used to find out what causes"
	@echo " the error."
	@echo ""
	@echo " Related help topics: verbose-help"

progs-help:
	@echo " Help for 'make progs'"
	@echo " 'make progs' goes through the program list given at the beginning of the"
	@echo " makefile and checks whether these programs can be found. If other programs"
	@echo " are available which can replace a program given here, the makefile needs"
	@echo " to be changed accordingly."

show-pkg-help:
	@echo " Help for 'make show-pkg'"
	@echo " 'make show-pkg' shows a list of all latex packages that are necessary to"
	@echo " process the document. Note that some of these packages are part of bigger"
	@echo " packages including several style files."
	@echo " A list of packages used to create the document is given in an appendix of the"
	@echo " document."

chk-pkg-help:
	@echo " Help for 'make chk-pkg'"
	@echo " 'make chk-pkg' tries to locate the .sty files used by the TeX sources. Note"
	@echo " that you need to have a filename database that locate can use. Also note that"
	@echo " locate only shows the location of the files, not whether these files are actually"
	@echo " the correct ones to be used."

#======================================================================
# make targets in understandable format

# create pdf
pdf: $(THESIS).pdf

# create dvi
dvi: $(THESIS).dvi

# create ps
ps: $(THESIS).ps

# debugging call to latex, showing all output which is otherwise suppressed
verbose:
	@$(LATEX) $(THESIS)

# parse sourcefiles and only show erros, warnings and over/underfull boxes
check:
	@echo "checking source file(s)..."
	@$(LATEX) -interaction=nonstopmode $(THESIS) >$(OUT); true
	@grep $(ERROR) $(THESIS).log; true
	@grep $(WARNING) $(THESIS).log; true
	@grep $(NOFILE) $(THESIS).log; true
	@grep $(OVERFULL) $(THESIS).log; true
	@grep $(UNDERFULL) $(THESIS).log; true

# check whether all necessary programs are available and can be found
progs:
	@for p in $(REQUIRED); do \
		loc=`which $$p 2>$(OUT)`; \
		if [ "$$?" = "0" ]; then echo "$$loc ... OK"; \
		else echo "$$p: ERROR!";\
		fi; \
	done;

# show latex packages and documentclass, may need some better formatting
# list all packages referenced via \usepackage, ignoring those commented out
show-pkg:
	@echo "Documentclass used: "
	@sed -n -e '/\\documentclass/,/}/p' $(THESIS).tex | tr -d '\r' | tr -d '\t' | sed -r 's/%.*//;s/ //g;s/,/, /g' | tr -d '\n' | fold -s --width 79
	@echo
	@echo "Packages loaded via \usepackage: "
	@echo $(PACKAGES) | sed 's/.sty//g;s/ /, /g' | fold -s --width=79
	@echo

chk-pkg:
	@loc=`locate $(CLASS)`>$(OUT); \
	if [ "$$?" = "0" ]; then echo "$$loc ... OK" | sed -r 's/.*\/l?a?tex\///'; \
	else echo "$(CLASS) ... ERROR"; fi;
	@for p in $(PACKAGES); do \
		loc=`locate */$$p`>$(OUT); \
		if [ "$$?" = "0" ]; then echo "$$loc ... OK" | sed -r 's/.*\/l?a?tex\///'; \
		else echo "$$p not found!"; \
		fi; \
	done;
	@echo

#======================================================================
# targets as filenames

# creation of pdf depends on existence of bibliography file (bbl), index (ind)
# and glossary (gls)
# if all these files are up to date, pdflatex is run, the logfile is checked 
# for changed labels and pdflatex is rerun if necessary
# the final touch to the required files prevents reworking all of them if 
# make dvi/pdf/ps is called again

$(THESIS).pdf: $(THESIS).bbl $(THESIS).ind $(THESIS).gls $(PDFFROMEPS) $(PDFFROMFIG) \
$(PDFFROMSVG) $(PDFFROMPLT)
	@echo "Running pdfLaTeX..."
	@$(PDFLATEX) $(THESIS) >$(OUT)
	@while grep $(RERUN) $(THESIS).log >$(OUT); do \
		echo "pdfLaTeX needs to be run again..."; $(PDFLATEX) $(THESIS) >$(OUT); \
	done
	@echo "PDF creation finished!"
	@touch $(THESIS).bbl $(THESIS).ind $(THESIS).gls $(THESIS).pdf

# creation of dvi depends on existence of bibliography file (bbl), index (ind)
# and glossary (gls)
# if all these files are up to date, latex is run, the logfile is checked 
# for changed labels and latex is rerun if necessary
# the final touch to the required files prevents reworking all of them if 
# make dvi/pdf/ps is called again

$(THESIS).dvi: $(THESIS).bbl $(THESIS).ind $(THESIS).gls
	@echo "Running LaTeX..."
	@$(LATEX) $(THESIS) >$(OUT)
	@while grep $(RERUN) $(THESIS).log >$(OUT); do \
		echo "LaTeX needs to be run again..."; $(LATEX) $(THESIS) >$(OUT); \
	done
	@echo "DVI creation finished!"
	@touch $(THESIS).bbl $(THESIS).ind $(THESIS).gls $(THESIS).dvi


# creation of ps file only depends on the existence of the dvi which is 
# converted using dvips
$(THESIS).ps: $(THESIS).dvi
	@echo "Running dvips..."
	@dvips -q $(THESIS) >$(OUT)
	@echo "PS creation finished!"

#======================================================================
# intermediate targets to get the dependencies

# bibliography file, depending on the literature database and the auxiliary
# file
# bibliography is simply created by running bibtex

$(THESIS).bbl bibtex: $(THESIS).aux $(BIB)
	@if grep '\\citation{' *.aux >$(OUT); then \
		echo "Running BibTeX...."; $(BIBTEX) $(THESIS) >$(OUT); \
	else \
		echo "No need to run BibTeX, because no citations found in *.aux files."; \
	fi;

# the files for glossary and index depend on files that are created
# during the first run of LaTeX
# the corresponding files are created by running makeindex

# glossary
$(THESIS).gls glossary: $(THESIS).glo
	@echo "Creating glossary..."
	@$(MAKEIDX) -q -s nomencl.ist -t $(THESIS).glg -o $(THESIS).gls $(THESIS).glo >$(OUT)

# index
$(THESIS).ind index: $(THESIS).idx
	@echo "Creating index file..."
	@$(MAKEIDX) -q $(THESIS) >$(OUT)

# the most basic auxiliary files that need to be created for all subsequent
# runs
# these only depend on the source tex files

$(THESIS).aux $(THESIS).idx $(THESIS).glo: $(TEXFILES) $(EPSFROMJPG) $(EPSFROMPDF)\
$(EPSFROMPNG) $(EPSFROMFIG) $(EPSFROMSVG) $(EPSFROMPLT)
	@echo "Creating auxiliary files..."
	@-$(LATEX) -interaction=nonstopmode $(THESIS) >$(OUT)
	@if grep $(ERROR) $(THESIS).log >$(OUT); then \
		echo "There were errors. Check your source files and try 'make verbose' to find the problem."; \
	else while grep $(RERUN) $(THESIS).log >$(OUT); do \
		echo "LaTeX needs to be run again..."; $(LATEX) $(THESIS) >$(OUT); \
	done; fi;
	@touch $(THESIS).idx

images: $(EPSFROMJPG) $(EPSFROMPDF) $(EPSFROMPNG) $(PDFFROMEPS) $(EPSFROMFIG) $(PDFFROMFIG) $(EPSFROMSVG) $(PDFFROMSVG)

plots: $(EPSFROMPLT) $(PDFFROMPLT)

$(EPSFROMPDF): %.eps : %.pdf
	@echo "Converting $< to $@..."
	@$(GS) -sDEVICE=epswrite -sOutputFile=$@ -r96 -dNOPAUSE -dBATCH $< >$(OUT)

$(EPSFROMPNG): %.eps : %.png
	@echo "Converting $< to $@..."
	@$(CONVERT) -compress Zip $< eps3:$@
	@touch $< $@

$(EPSFROMJPG): %.eps : %.jpg
	@echo "Converting $< to $@..."
	@$(CONVERT) -compress Zip $< eps3:$@
	@touch $< $@

$(PDFFROMEPS): %.pdf : %.eps
	@echo "Converting $< to $@..."
	@epstopdf $<

$(EPSFROMFIG): %.eps : %.fig
	@echo "Converting $< to $@..."
	@$(FIG2DEV) -L eps $< > $@

$(PDFFROMFIG): %.pdf : %.fig
	@echo "Converting $< to $@..."
	@$(FIG2DEV) -L pdf $< > $@

$(EPSFROMSVG): %.eps : %.svg
	@loc=`which $(INKSCAPE) 2>$(OUT)`;
	@if [ "$$?" = "0" ]; then \
		echo "Converting $< to $@..."; \
		$(INKSCAPE) -z -file=$< --export-eps=$@; \
 	else \
	    echo "Could not convert $< to $@: $(INKSCAPE) is not installed."; \
	fi;

$(PDFFROMSVG): %.pdf : %.eps
	@echo "Converting $< to $@..."
	@$(EPSTOPDF) $<

$(EPSFROMPLT): %.eps : %.plt
	@echo "Converting $< to $@..."
	@echo "set terminal postscript eps enhanced color solid" >helper.plot
	@echo "set output '$@'" >>helper.plot
	@$(PLOT) helper.plot $<
	@rm -f helper.plot

$(PDFFROMPLT): %.pdf : %.plt
	@echo "Converting $< to $@..."
	@echo "set terminal pdf enhanced" >helper.plot
	@echo "set output '$@'" >>helper.plot
	@$(PLOT) helper.plot $<
	@rm -f helper.plot
	
#======================================================================
# targets to clean up after operation

# simple deletion of all intermediate files
clean:
	@echo "Throwing intermediate files away..."
	@rm -f *.aux *.bbl *.blg *.ent *.glg *.glo *.gls *.idx *.ilg \
	       *.ind *.ist *.loa *.lof *.log *.lot *.mpx *.out *.toc *.tpt *.thm

# in addition, one can remove everything but the source files
mrproper: clean
	@echo "Removing result files, leaving only source files..."
	@rm -f $(THESIS).ps $(THESIS).pdf $(THESIS).dvi

dvionly: dvi clean

psonly: ps clean
	@echo "Removing temporary result files..."
	@rm -f $(THESIS).dvi

pdfonly: pdf clean
	@echo "Removing temporary result files..."
	@rm -f $(THESIS).dvi
