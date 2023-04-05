%
% $Id: cs-paper.cls 2668 2008-06-06 12:54:55Z jozinke $
%
% SUMMARY:
%
% This class is based on the KOMA-class 'scrartcl'.
%
% Additionally, quite a few packages are included. They have been
% selected very carefully and there has been no incompatibility yet.
%
% This class provides several usefull packages, intitiates some of its
% options and uses its commands in order to provide common page
% styles, common float environments, common report components (like
% index, glossary, a.s.o.) and others.
% Depending on the options
%  * 'german',
%  * 'twoside'
% different packages are included and different options are set. If
% you want to do some decisions basing on these options you
% can use the corresponding conditionals:
%  * '\if@german',
%  * '\if@oneside',
%  * '\if@twoside'
%
% This class provides provides additional parameters:
%  * Named colour:
%     + 'cslightbluecolor'
%    This colour is used to emphasise references in the resulting
%    document (e.g. links, cross references, cites, menus). By default,
%    this colour is a pretty nice shade of blue. If you want to
%    redefine its value, please use '\definecolor'. For printing
%    purposes, you might want to choose¹ black:
%     + '\definecolor{cslightbluecolor}{rgb}{0,0,0}'
%  * Few page styles
%     + 'chapterstyle',
%     + 'appendixstyle'
%    They can be initiated using '\pagestyle'. Starting the chapters,
%    it might be clever to call¹:
%     + '\pagestyle{chapterstyle}'
%
% ¹This you surely have to call in your own tex file!
%

%
% HEADER OF THE CLASS
%
% What we do need, and what we do provide.
%
\NeedsTeXFormat{LaTeX2e}
\ProvidesClass{cs-paper}[2008/06/03]

%
% INITIALISATION
%
% Only few things before we go over to the options, packages and main
% things.
%
% creating some conditionals with \newif
\newif\if@german\@germanfalse
\newif\if@oneside\@onesidetrue
\newif\if@twoside\@twosidefalse

%
% DECLARATION OF OPTIONS
%
% Here, the options are dealt with. In case they are specified, the
% corresponding LaTeX-command will be executed.
%
% override conditionals values by corresponding options
\DeclareOption{german}{\@germantrue}
\DeclareOption{twoside}{\@twosidetrue \@onesidefalse}

%
% PROCESSING OPTIONS
%
% This is the place, where all options are identified and consequences
% happen (see 'DECLARATION OF OPTIONS').
%
\ProcessOptions\relax % prevent undesirable commands (LaTeX-Book A.4.4)

%
% LOADING OF PACKAGES
%
% Now, several packages will be included. Some of them will be
% configured using local options. The complete list of required
% packages can be found in the summary above.
%
% load basic KOMA-class that now is going to be extended
\LoadClassWithOptions{scrartcl}

%
% MAIN PART OF THE CLASS
%
% Now we can configure all the things we think a report should look
% like.
% Additionally, we provide some commands that can ease author's life.
%

% include common packages and macros
\input{cs-common}

%
% PACKAGES
%

% formating captions
\RequirePackage[format=hang,
                margin=10pt,
                font=small,
                labelfont=bf]{caption}

% include subfigures
\RequirePackage{subfig}

% extended theorem environment
\RequirePackage[amsmath,
                hyperref,
                thmmarks,
                thref]{ntheorem}

%
% MACROS
%

% more space between lines but not footnotes
\onehalfspacing

% handle document compilation in a different way
\ifpdfoutput{
  % set hyperref for pdf output
  \hypersetup{pdftex}
  \pdfcompresslevel=9
}{
  % set hyperref for dvi/ps output
  \hypersetup{dvips,
              pdfborder=0}
}

% clear all header and footer definitions so far
\clearscrheadfoot

% define [right] and {left} mark
\automark[section]{chapter}

% define page some styles
\newpagestyle{chapterstyle}{{\leftmark\hfill}{\hfill\rightmark}{\leftmark\hfill}}{{\pagemark\hfill}{\hfill\pagemark}{\hfill\pagemark\hfill}}
\newpagestyle{appendixstyle}{{\leftmark\hfill}{\hfill\leftmark}{\leftmark\hfill}}{{\pagemark\hfill}{\hfill\pagemark}{\hfill\pagemark\hfill}}

% format footnote
\deffootnote[1.5em]{1.5em}{1em}{\textsuperscript{\thefootnotemark}}

% initialise index
\makeindex

% initialise glossary
\makeglossary

% define additional float environment
\newfloat{algorithm}{htbp}{loa}[section]
\floatname{algorithm}{\iflanguage{ngerman}{Algorithmus}{Algorithm}}
\newcommand{\listofalgorithms}{\listof{algorithm}{\iflanguage{ngerman}{Algorithmenverzeichnis}{List of Algorithms}}}

% author tool missing command
\newcommand{\missing}[1]{\textcolor{blue}{(\marginpar[\hfill\bf$\longrightarrow$]{\bf$\longleftarrow$}#1)}}

% sub figures
\newcommand{\subfigs}[5][~]{%
  \begin{figure}[htbp]%
    \begin{center}%
    \subfloat[][]{%
      \label{#5:a}%
      \includegraphics[width=.45\textwidth]{#2}%
    }\hspace{0.05\textwidth}%
    \subfloat[][]{%
      \label{#5:b}%
      \includegraphics[width=.45\textwidth]{#3}%
    }%
    \ifthenelse{\equal{#1}{~}}{%
      \figcaption{#4}%
    }{%
      \figcaption[#1]{#4}%
    }%
    \label{#5}%
    \end{center}%
  \end{figure}%
}

% fully layouted subref
\newcommand{\sref}[1]{\begin{NoHyper}\textbf{\subref{#1}}\end{NoHyper}}

% definition/configuration of the theorem environment
% set layout
\theorembodyfont{\itshape}
\theoremheaderfont{\normalfont\bfseries}
\theoremnumbering{arabic}
\theoremseparator{}
\theoremstyle{plain} % does not work with beamer
\theoremsymbol{\ensuremath{_\Box}}
% define some theorems
\newtheorem{theorem}{Theorem}
\newtheorem{prop}{\iflanguage{ngerman}{Satz}{Proposition}}
\newtheorem{coroll}{\iflanguage{ngerman}{Korollar}{Corollary}}
\newtheorem{lemma}{Lemma}
% change layout a bit
\theorembodyfont{\upshape}
% define some more theorems
\newtheorem{example}{\iflanguage{ngerman}{Beispiel}{Example}}
\newtheorem{remark}{\iflanguage{ngerman}{Anmerkung}{Remark}}
\newtheorem{definition}{Definition}
% change layout a bit
\theorembodyfont{\normalfont}
\theoremheaderfont{\scshape}
\theoremstyle{nonumberplain}
\theoremsymbol{\ensuremath{_\blacksquare}}
% define some more theorems
\newtheorem{proof}{\iflanguage{ngerman}{Beweis}{Proof}}
% set qed symbol
\qedsymbol{\ensuremath{_\blacksquare}}

