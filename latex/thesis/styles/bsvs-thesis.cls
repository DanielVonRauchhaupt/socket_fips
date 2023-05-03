%
% $Id: bsvs-thesis.cls 3918 2009-06-18 14:43:18Z jozinke $
%
% SUMMARY:
%
% This class is based on the class 'cs-thesis'.
%
% Additionally, it contains several commands that might be usefull
% writing a (diploma) thesis. This includes common structural parts
% like title page, bibliographic information, acknowledgment,
% declaration of authorship, abstract and others.
% Basing on this class, it should be very easy to create a (diploma)
% thesis at the chair of 'Operating Systems & Distributed Systems',
% here in Potsdam at the 'Institute of Computer Sciences' at the
% 'Faculty of Mathematics and Natural Sciences'.
% The only thing you now have to to is to fill the thesis with some
% knowledge.
%
% TODO:
% 
% + '\makeauthorship' und '\makeabstract' müssen ebenfalls auf
%   unnummerierten Seiten erscheinen!
%

%
% HEADER OF THE CLASS
%
% What we do need, and what we do provide.
%
\NeedsTeXFormat{LaTeX2e}
\ProvidesClass{bsvs-thesis}[2008/06/03]

%
% INITIALISATION
%
% creating some conditionals with \newif
\newif\if@semidraft\@semidraftfalse

%
% DECLARATION OF OPTIONS
%
% Here, the options are dealt with. In case they are specified, the
% corresponding LaTeX-command will be executed.
%
% override conditionals values by corresponding options
\DeclareOption{semidraft}{\@semidrafttrue}
\DeclareOption{draft}{\@semidrafttrue}

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
% load basic 'cs-thesis' that now is going to be extended
\LoadClassWithOptions{cs-thesis}

%
% MAIN PART OF THE CLASS
%
% Definition of several commands in order to provide a common BSVS
% thesis.
%

% First, import the configuration data.
\InputIfFileExists{bsvs-thesis.cfg}{}{\ClassError{bsvs-thesis.cls}{Missing file [bsvs-thesis.cfg]!}{Unpack all bsvs-thesis files again.}}
\usepackage{pifont}% http://ctan.org/pkg/pifont
\usepackage{multirow}
\hypersetup{breaklinks=true}

\newcommand{\cmark}{\ding{51}}%
\newcommand{\xmark}{\ding{55}}%
\input{bsvs-common}

\if@semidraft
  \usepackage[
  %	notref
  %	notcite
  ]{showkeys}
\fi

\if@semidraft
  \usepackage{type1cm}
  \usepackage{eso-pic}
  \makeatletter
  \AddToShipoutPicture{%
    \setlength{\@tempdimb}{.5\paperwidth}%
    \setlength{\@tempdimc}{.5\paperheight}%
    \setlength{\unitlength}{1pt}%
    \put(\strip@pt\@tempdimb,\strip@pt\@tempdimc){%
      \makebox(0,0){%
        \rotatebox{45}{%
          \textcolor[gray]{0.95}{%
            \iflanguage{ngerman}{\fontsize{3cm}{3cm}\selectfont{ENTWURF}}{\fontsize{3cm}{3cm}\selectfont{DRAFT}}%
          }%
        }%
      }%
    }%
  }
  \AddToShipoutPicture{%
    \setlength{\@tempdimb}{.5\paperwidth}%
    \setlength{\@tempdimc}{.02\paperheight}%
    \setlength{\unitlength}{1pt}%
    \put(\strip@pt\@tempdimb,\strip@pt\@tempdimc){%
      \makebox(0,0){%
        \textcolor[gray]{0.75}{%
         \fontsize{.5cm}{.5cm}\selectfont{\iflanguage{ngerman}{--- ENTWURF --- \today{} ---}{--- DRAFT --- \today{} ---}}%
        }%
      }%
    }%
  }
  \makeatother
\fi

% title
\title{\bsvsTitle\\{\smaller\bsvsSubtitle}}

% author
\author{{\smaller\iflanguage{ngerman}{von}{by}}\\[0.5em]\bsvsAuthortitle~\bsvsAuthorname~\bsvsAuthorsurname}

% date
\date{\iflanguage{ngerman}{\bsvsPlace, den \bsvsDate}{\bsvsPlace, \bsvsDate}}

% publishers
\publishers{\bsvsLogo\\\bsvsUni\\\bsvsDepart\\\bsvsProf\\[1.2em]\iflanguage{ngerman}{Aufgabenstellung und Betreuung:}{Supervisors:}\\\ifthenelse{\equal{\bsvsAssayer}{~}}{\bsvsAdvisorone\\\bsvsAdvisortwo}{\bsvsAssayer\\\bsvsAdvisorone}}
\lowertitleback{\textbf{\bsvsAuthorsurname,~\bsvsAuthorname}\\\texttt{\bsvsAuthoremail}\\\bsvsTitle\\\bsvsSubject,~\bsvsDepart\\\bsvsUni,~\bsvsMonth}

% dedication
\dedication{\bsvsThanks}

% Prepare declaration of authorship.
% This declaration keeps german, even if the thesis is written in english!
% As the thesis is done at the _german_ potsdam university, the formal
% parts have to be german too.
\newcommand{\makeauthorship}{
  \chapter*{Selbständigkeitserklärung}
  \thispagestyle{empty}
  Hiermit erkläre ich, dass ich die vorliegende Arbeit selbständig angefertigt, nicht anderweitig zu Prüfungszwecken vorgelegt und keine anderen als die angegebenen Hilfsmittel verwendet habe. Sämtliche wissentlich verwendeten Textausschnitte, Zitate oder Inhalte anderer Verfasser wurden ausdrücklich als solche gekennzeichnet.\\[2ex]
  \iflanguage{ngerman}{\bsvsPlace, den \bsvsDate\\[6ex]}{\bsvsPlace, \bsvsDate\\[6ex]}
  {\flushleft
  \newlength\us
  \settowidth{\us}{-\bsvsAuthorsurname~\bsvsAuthorname-}
  \begin{tabular}{p{\us}}\hline
  \centering\footnotesize \bsvsAuthorname~\bsvsAuthorsurname
  \end{tabular}}
}

% abstract
\newcommand{\makeabstract}{

  \ifthenelse{\equal{\bsvsAbstract}{~}}{}{
    \begin{abstract}
    \bsvsAbstract
    \end{abstract}

  }
}

\newcommand{\makezusammenfassung}{
\begin{dtZusammenfassung}
\bsvsZusammenfassung
\end{dtZusammenfassung}
}
% titlepage
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
    {\titlefont\huge \@title\par}
    \vskip 20\p@
    \par
    \hrule height 1pt
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
    \vskip 60\p@
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
