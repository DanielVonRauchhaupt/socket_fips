%
% This is class file specifying all packages to include, constants
%

\NeedsTeXFormat{LaTeX2e}
\ProvidesClass{cs-thesis}[2024/05/03]

\InputIfFileExists{thesis.cfg}{}{\ClassError{cs-thesis.cls}{Missing file [thesis.cfg]!}{Check for the missing file.}}

\LoadClassWithOptions{scrreprt}



%%%%%%%%%%%%%%%%
%%% Packages %%%
%%%%%%%%%%%%%%%%

\RequirePackage{caption}
\RequirePackage{subcaption}
\RequirePackage{color}
\RequirePackage{listings}
\RequirePackage[hyperfootnotes=false,
pdfpagelabels=true]{hyperref}
\RequirePackage[automark,
                headsepline]{scrlayer-scrpage}
\RequirePackage{relsize}
\RequirePackage{graphicx}
\RequirePackage{ifthen}
\RequirePackage[ngerman,english]{babel}
\RequirePackage[printonlyused]{acronym}
\RequirePackage{float}
\RequirePackage{scrhack} % to solve warning of float
\RequirePackage{makeidx}
\RequirePackage[T1]{fontenc}
% \RequirePackage{lmodern}

\usepackage[%
backend=biber      % biber or bibtex
,style=\citationstyle  % numerical-compressed
,sorting=none        % no sorting
,sortcites=true      % some other example options ...
,block=none
,indexing=false
,citereset=none
,isbn=true
,url=true
,doi=false  % prints doi
,backref
]{biblatex}
\RequirePackage{csquotes}



%%%%%%%%%%%%%%%%%
%%% Constants %%%
%%%%%%%%%%%%%%%%%

% color used for links
\definecolor{university100blue}{rgb}{0,0.18825,0.36864}



%%%%%%%%%%%%%%%%
%%% Settings %%%
%%%%%%%%%%%%%%%%

% define page styles
\newpagestyle{chapterstyle}{{\leftmark\hfill}{\hfill\rightmark}{\leftmark\hfill}}{{\pagemark\hfill}{\hfill\pagemark}{\hfill\pagemark\hfill}}
\newpagestyle{appendixstyle}{{\leftmark\hfill}{\hfill\leftmark}{\leftmark\hfill}}{{\pagemark\hfill}{\hfill\pagemark}{\hfill\pagemark\hfill}}

% format source listings
\lstset{numbers=left,
  showstringspaces=false,
  frame={tb},
  captionpos=b,
  lineskip=0pt,
  basicstyle=\ttfamily,
  extendedchars=true,
  stepnumber=1,
  numberstyle=\small,
  xleftmargin=1em,
  breaklines
}

% Set some 'hyperref' meta data.
\hypersetup{
    plainpages=false,
    colorlinks=true,
    breaklinks=true,
    citecolor=university100blue,
    linkcolor=university100blue,
    menucolor=university100blue,
    urlcolor=university100blue,
    pdftitle    = {\thesisTitle},
    pdfsubject  = {\thesisSubject,~\thesisDate},
    pdfauthor   = {\thesisAuthorname~\thesisAuthorsurname,~\thesisAuthoremail},
    pdfkeywords = {\thesisKeywords}%,
%   pdfcreator  = {pdfTeX with Hyperref and Thumbpdf},
%   pdfproducer = {LaTeX, hyperref, thumbpdf}
}



%%%%%%%%%%%%%%
%%% MACROS %%%
%%%%%%%%%%%%%%

% subject
\subject{\thesisSubject}

% title
\title{\thesisTitle\\{\smaller\thesisSubtitle}}

% author
\author{{\smaller\iflanguage{ngerman}{von}{by}}\\[0.5em]\thesisAuthortitle~\thesisAuthorname~\thesisAuthorsurname}

% date
\date{\thesisPlace, \thesisDate}

% publishers
\publishers{\thesisLogo\\\thesisUni\\\thesisDepart\\\thesisProf \vskip 20\p@ \rule{9.9cm}{0.5pt} \vskip 20\p@ Supervisor(s):\\\ifthenelse{\equal{\thesisAssayer}{~}}{\thesisAdvisorOne\\\thesisAdvisorTwo}{\thesisAssayer\\\thesisAdvisorOne}}
\lowertitleback{\textbf{\thesisAuthorsurname,~\thesisAuthorname}\\\texttt{\thesisAuthoremail}\\\thesisTitle\\\thesisSubject,~\thesisDepart\\\thesisUni,~\thesisMonth}

% dedication
\dedication{\thesisThanks}



%%%%%%%%%%%%%%%%%%%%%%
%%% (New) Commands %%%
%%%%%%%%%%%%%%%%%%%%%%

% Title page definition
% font overview: https://www.overleaf.com/learn/latex/Font_typefaces
\makeatletter
\renewcommand*\maketitle[1][1]{\begin{titlepage}%
    \setcounter{page}{1}
    \let\footnotesize\small
    \let\footnoterule\relax
    \let\footnote\thanks
    \renewcommand*\thefootnote{\@fnsymbol\c@footnote}%
    \let\@oldmakefnmarnoindek\@makefnmark
    \renewcommand*{\@makefnmark}{\rlap\@oldmakefnmark}
    \ifx\@extratitle\@empty \else
        \noindent\@extratitle\next@tpage\cleardoublepage
        \thispagestyle{empty}
    \fi
    \begin{center}
    {\fontfamily{cmss} \textbf{ \huge \@title}}
    \vskip 10\p@
    \par
    \hrule
    \par
    \vskip 20\p@
    \ifx\@subject\@empty \else
        {\huge \@subject \par}
    \fi
    \vskip 20\p@
    {\huge \lineskip 0.75em
    \begin{tabular}[t]{c}
        \@author
    \end{tabular}\par}
    \vskip 50\p@
    {\Large \@publishers \par}
    \vskip 50\p@
    \vfil\null
    {\large \@date \par}
    \end{center}\par
    \if@twoside\next@tpage
        \noindent\begin{minipage}[t]{\textwidth}
        \@uppertitleback
        \end{minipage}\par
        \vfill
        \noindent\begin{minipage}[b]{\textwidth}
        \@lowertitleback
        \end{minipage}
    \fi
    \ifx\@dedication\@empty \else
        \next@tpage\null\vfill
        {\Large \@dedication \par}
        \vskip \z@ \@plus3fill
        \if@twoside \next@tpage\cleardoublepage \fi
    \fi
    \end{titlepage}
    \setcounter{footnote}{0}%
    \global\let\thanks\relax
    \global\let\maketitle\relax
    \global\let\@thanks\@empty
    \global\let\@author\@empty
    \global\let\@date\@empty
    \global\let\@title\@empty
    \global\let\@extratitle\@empty
    \global\let\@titlehead\@empty
    \global\let\@subject\@empty
    \global\let\@publishers\@empty
    \global\let\@uppertitleback\@empty
    \global\let\@lowertitleback\@empty
    \global\let\@dedication\@empty
    \global\let\author\relax
    \global\let\title\relax
    \global\let\extratitle\relax
    \global\let\titlehead\relax
    \global\let\subject\relax
    \global\let\publishers\relax
    \global\let\uppertitleback\relax
    \global\let\lowertitleback\relax
    \global\let\dedication\relax
    \global\let\date\relax
    \global\let\and\relax
}
\makeatother

% Prepare declaration of authorship.
% This declaration keeps german, even if the thesis is written in english!
% As the thesis is done at the _german_ potsdam university, the formal
% parts have to be german too.
\newcommand{\makeauthorship}{
  \chapter*{Selbständigkeitserklärung}
  \thispagestyle{empty}
  Hiermit erkläre ich, dass ich die vorliegende Arbeit selbständig angefertigt, nicht anderweitig zu Prüfungszwecken vorgelegt und keine anderen als die angegebenen Hilfsmittel verwendet habe. Sämtliche wissentlich verwendeten Textausschnitte, Zitate oder Inhalte anderer Verfasser wurden ausdrücklich als solche gekennzeichnet.\\[2ex]
  \thesisPlace, den \thesisDateGerman\\[6ex]
  {\flushleft
  \newlength\us
  \settowidth{\us}{-\thesisAuthorsurname~\thesisAuthorname-}
  \begin{tabular}{p{\us}}\hline
  \centering\footnotesize \thesisAuthorname~\thesisAuthorsurname
  \end{tabular}}
}

% abstract
\newcommand{\makeabstract}{
    \ifthenelse{\equal{\thesisAbstract}{~}}{}{
    \begin{abstract}
        \thesisAbstract
    \end{abstract}
    }
}

% Zusammenfassung; required to have german abstract as well
\newcommand{\makezusammenfassung}{
    \ifthenelse{\equal{\thesisAbstract}{~}}{}{
      \renewcommand{\abstractname}{Deutsche Zusammenfassung}
      \begin{abstract}
        \thesisZusammenfassung
      \end{abstract}
    }
}

% define additional float environment
\newfloat{algorithm}{htbp}{loa}[chapter]
\floatname{algorithm}{Algorithm}
\newcommand{\listofalgorithms}{\listof{algorithm}{List of Algorithms}}
