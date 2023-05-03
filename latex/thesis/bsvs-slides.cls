%
% $Id: bsvs-slides.cls 8749 2011-04-21 11:54:29Z fudickar $
%
% SUMMARY:
%
% This class is based on the class 'cs-slides'.
%
% Additionally, it contains several commands that might be usefull
% creating a presentation. This includes common structural parts
% like title page or bibliographic information.
% Basing on this class, it should be very easy to create slides
% at the chair of 'Operating Systems & Distributed Systems',
% here in Potsdam at the 'Institute of Computer Sciences' at the
% 'Faculty of Mathematics and Natural Sciences'.
% The only thing you now have to to is to fill the slides with some
% knowledge.
%

%
% HEADER OF THE CLASS
%
% What we do need, and what we do provide.
%
\NeedsTeXFormat{LaTeX2e}
\ProvidesClass{bsvs-slides}[2008/02/05]

%
% INITIALISATION
%

%
% DECLARATION OF OPTIONS
%
% Here, the options are dealt with. In case they are specified, the
% corresponding LaTeX-command will be executed.
%

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
% packages can be found at the summary above.
%
% load basic 'cs-slides' that now is going to be extended
\LoadClassWithOptions{cs-slides}

%
% MAIN PART OF THE CLASS
%
% Definition of several commands in order to provide a common BSVS
% presentation.
%

% First, import the configuration data.
\InputIfFileExists{bsvs-slides.cfg}{}{\ClassError{bsvs-slides.cls}{Missing file [bsvs-slides.cfg]!}{Unpack all bsvs-slides files again.}}

\input{bsvs-common}

% Set theme values similar to CambridgeUS).
\useinnertheme{rectangles}
\useoutertheme{infolines}

\setbeamerfont{block title}{size={}}
\setbeamercolor{titlelike}{parent=structure,bg=white}

% Set color values similar to seagull.
\setbeamercolor*{normal text}{fg=black,bg=white}
\setbeamercolor*{alerted text}{fg=black}
\setbeamercolor*{example text}{fg=black}
\setbeamercolor*{structure}{fg=black}

\setbeamerfont{alerted text}{series=\bfseries}

\setbeamercolor*{palette primary}{fg=white,bg=university60blue}
\setbeamercolor*{palette secondary}{fg=black,bg=university20blue}
\setbeamercolor*{palette tertiary}{fg=white,bg=university100blue}
\setbeamercolor*{palette quaternary}{fg=white,bg=university100blue}

\setbeamercolor{sidebar}{bg=university20blue}

\setbeamercolor*{palette sidebar primary}{fg=black}
\setbeamercolor*{palette sidebar secondary}{fg=black}
\setbeamercolor*{palette sidebar tertiary}{fg=black}
\setbeamercolor*{palette sidebar quaternary}{fg=black}

\setbeamercolor*{item projected}{fg=black,bg=university20blue}

\setbeamercolor*{block title}{fg=black,bg=university40blue}
\setbeamercolor*{block title alerted}{fg=black,bg=university40blue}
\setbeamercolor*{block title example}{fg=black,bg=university40blue}

\setbeamercolor*{block body}{fg=black,bg=university20blue}
\setbeamercolor*{block body alerted}{fg=black,bg=university20blue}
\setbeamercolor*{block body example}{fg=black,bg=university20blue}

\setbeamercolor*{separation line}{}
\setbeamercolor*{fine separation line}{}

% Set transparency for uncovered items.
\setbeamercovered{transparent=30}

% on handout 4 frames per page
\only<handout>{
\pgfpagesuselayout{4 on 1}[a4paper,border shrink=5mm,landscape]
}

% notes on second screen
%\setbeameroption{notes on second screen}

% remove navigation
\beamertemplatenavigationsymbolsempty

% title
\title[\bsvsShortTitle]{\bsvsTitle\\{\smaller\bsvsSubtitle}}

% author
\author[\bsvsAuthorname~\bsvsAuthorsurname]{\bsvsAuthortitle~\bsvsAuthorname~\bsvsAuthorsurname}

% date
\date[\bsvsDate]{\iflanguage{ngerman}{\bsvsPlace, den \bsvsDate}{\bsvsPlace, \bsvsDate}}

% institute
%\institute[\bsvsUni]{\bsvsUni\\\bsvsDepart\\\bsvsProf\\[1.2em]}
\institute[\bsvsUni]{\bsvsUni\\\bsvsDepart\\\bsvsProf\\[1.2em]}

% logo
\logo{\bsvsLogo}

% keywords
\keywords{\bsvsKeywords}

% titlepage
\setbeamertemplate{title page}{
    \vskip0pt plus 1filll
    
    \begin{centering} 
        {\large\usebeamerfont{title}\usebeamercolor[fg]{title}\inserttitle}
        \vskip 5\p@
        \par
        \hrule height 1pt
        \par
        \vskip 5\p@
        {\normalsize\lineskip 0.75em
        \begin{tabular}[t]{c}
            \insertauthor
        \end{tabular}\par}
        \vskip 20\p@
        {\small \insertlogo\\\insertinstitute \par}
        \vskip 5\p@
        {\footnotesize \insertdate \par}
    \end{centering}
    
    \vskip0pt plus 1filll
}

% remove logo from sidebar
\setbeamertemplate{sidebar right}
{
  \vfill%
  \llap{
  \hskip0.1cm}%
  \vskip2pt%
  \vfill%
  \llap{\usebeamertemplate***{navigation symbols}\hskip0.1cm}%
  \vskip2pt%
}

% footline beautifications
\setbeamertemplate{footline}
{
  \leavevmode%
  \hbox{%
  \begin{beamercolorbox}[wd=.333333\paperwidth,ht=2.25ex,dp=1ex,center]{author in head/foot}%
    \usebeamerfont{author in head/foot}
%    \insertshortauthor~~(\insertshortinstitute)
% Nur wenn Institut existiert auch einfuegen
\insertshortauthor
\if\beamer@shortinstitute\relax
\else
  ~~(\insertshortinstitute)
\fi
  \end{beamercolorbox}%
  \begin{beamercolorbox}[wd=.333333\paperwidth,ht=2.25ex,dp=1ex,center]{title in head/foot}%
    \usebeamerfont{title in head/foot}\insertshorttitle
  \end{beamercolorbox}%
  \begin{beamercolorbox}[wd=.333333\paperwidth,ht=2.25ex,dp=1ex,center]{date in head/foot}%  
    \iflanguage{ngerman}{Folie}{Frame}~~\insertframenumber{}~~\iflanguage{ngerman}{von}{of}~~\inserttotalframenumber\hspace*{26pt}
  \end{beamercolorbox}}%
  \vskip0pt%
  % logo on every frame in lower right corner
  \usebeamercolor[bg]{date in head/foot}  
  \begin{tikzpicture}[remember picture, overlay]
    \coordinate (bottom-right) at (\paperwidth-22pt,\paperheight-\paperheight+22pt);
    \fill[color=bg] (bottom-right) circle (26pt);
    \fill[color=white] (bottom-right) circle (22pt);
    \fill[color=bg] (bottom-right) circle (21pt); 
    \fill[color=white] (bottom-right) circle (20pt);  
    \put(327,6){\bsvsLogoSmall}
  \end{tikzpicture}
}
