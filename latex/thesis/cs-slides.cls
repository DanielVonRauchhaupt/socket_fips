%
% $Id: cs-slides.cls 2701 2008-06-17 09:43:00Z jozinke $
%
% SUMMARY:
%
% This class is based on the Beamer-class 'beamer'.
%
% Additionally, quite a few packages are included. They have been
% selected very carefully and there has been no incompatibility yet.
%
% This class provides several usefull packages, intitiates some of its
% options and uses its commands in order to provide common page
% styles, common float environments, common presentation components 
% and others.

% Depending on the option 'german', different packages are included 
% and different options are set.
% If you want to do some decisions basing on these options you
% can use the corresponding conditionals: '\if@german'.
%

%
% HEADER OF THE CLASS
%
% What we do need, and what we do provide.
%
\NeedsTeXFormat{LaTeX2e}
\ProvidesClass{cs-lides}[2008/06/03]

%
% INITIALISATION
%
% Only few things before we go over to the options, packages and main
% things.
%
% creating some conditionals with \newif
\newif\if@german\@germanfalse

%
% DECLARATION OF OPTIONS
%
% Here, the options are dealt with. In case they are specified, the
% corresponding LaTeX-command will be executed.
%
% override conditionals values by corresponding options
\DeclareOption{german}{\@germantrue}

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
% load basic Beamer-class that now is going to be extended
\LoadClassWithOptions{beamer}

%
% MAIN PART OF THE CLASS
%
% Now we can configure all the things we think a presentation should look
% like.
% Additionally, we provide some commands that can ease author's life.
%

% include common packages and macros
\input{cs-common}

% drawing package
\RequirePackage{tikz}

% nice formating of pages in pdf
\RequirePackage{pgfpages}

