%
% $Id: bsvs-paper.cls 2668 2008-06-06 12:54:55Z jozinke $
%
% SUMMARY:
%
% This class is based on the class 'cs-paper'.
%
% Additionally, it contains several commands that might be usefull
% writing a (diploma) paper. This includes common structural parts
% like title page, bibliographic information, acknowledgment,
% declaration of authorship, abstract and others.
% Basing on this class, it should be very easy to create a (diploma)
% paper at the chair of 'Operating Systems & Distributed Systems',
% here in Potsdam at the 'Institute of Computer Sciences' at the
% 'Faculty of Mathematics and Natural Sciences'.
% The only thing you now have to to is to fill the paper with some
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
\ProvidesClass{bsvs-paper}[2008/06/03]

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
% load basic 'cs-paper' that now is going to be extended
\LoadClassWithOptions{cs-paper}

%
% MAIN PART OF THE CLASS
%
% Definition of several commands in order to provide a common BSVS
% paper.
%

% First, import the configuration data.
\InputIfFileExists{bsvs-paper.cfg}{}{\ClassError{bsvs-paper.cls}{Missing file [bsvs-paper.cfg]!}{Unpack all bsvs-paper files again.}}

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
\author{\bsvsAuthortitle~\bsvsAuthorname~\bsvsAuthorsurname\\{\smaller\em\bsvsAuthoremail}}

% date
\date{}

% publishers
\publishers{\bsvsLogo\\\smaller\bsvsUni\\\bsvsDepart\\\bsvsProf}

% abstract
\newcommand{\makeabstract}{
  \ifthenelse{\equal{\bsvsAbstract}{~}}{}{
    \begin{abstract}
    {\textbf\bsvsAbstract}
    \end{abstract}\\\\
    \textbf{Keywords: \it\bsvsKeywords}
  }
}
