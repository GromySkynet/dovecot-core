/* A Bison parser, made by GNU Bison 3.8.2.  */

/* Bison interface for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2015, 2018-2021 Free Software Foundation,
   Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

/* DO NOT RELY ON FEATURES THAT ARE NOT DOCUMENTED in the manual,
   especially those whose name start with YY_ or yy_.  They are
   private implementation details that can be changed or removed.  */

#ifndef YY_VAR_EXPAND_PARSER_VAR_EXPAND_PARSER_H_INCLUDED
# define YY_VAR_EXPAND_PARSER_VAR_EXPAND_PARSER_H_INCLUDED
/* Debug traces.  */
#ifndef VAR_EXPAND_PARSER_DEBUG
# if defined YYDEBUG
#if YYDEBUG
#   define VAR_EXPAND_PARSER_DEBUG 1
#  else
#   define VAR_EXPAND_PARSER_DEBUG 0
#  endif
# else /* ! defined YYDEBUG */
#  define VAR_EXPAND_PARSER_DEBUG 0
# endif /* ! defined YYDEBUG */
#endif  /* ! defined VAR_EXPAND_PARSER_DEBUG */
#if VAR_EXPAND_PARSER_DEBUG
extern int var_expand_parser_debug;
#endif

/* Token kinds.  */
#ifndef VAR_EXPAND_PARSER_TOKENTYPE
# define VAR_EXPAND_PARSER_TOKENTYPE
  enum var_expand_parser_tokentype
  {
    VAR_EXPAND_PARSER_EMPTY = -2,
    VAR_EXPAND_PARSER_EOF = 0,     /* "end of file"  */
    VAR_EXPAND_PARSER_error = 256, /* error  */
    VAR_EXPAND_PARSER_UNDEF = 257, /* "invalid token"  */
    PERC = 258,                    /* PERC  */
    OCBRACE = 259,                 /* OCBRACE  */
    CCBRACE = 260,                 /* CCBRACE  */
    PIPE = 261,                    /* PIPE  */
    OBRACE = 262,                  /* OBRACE  */
    CBRACE = 263,                  /* CBRACE  */
    COMMA = 264,                   /* COMMA  */
    DOT = 265,                     /* DOT  */
    QUOTE = 266,                   /* QUOTE  */
    EQ = 267,                      /* EQ  */
    PLUS = 268,                    /* PLUS  */
    MINUS = 269,                   /* MINUS  */
    STAR = 270,                    /* STAR  */
    SLASH = 271,                   /* SLASH  */
    NAME = 272,                    /* NAME  */
    VALUE = 273,                   /* VALUE  */
    NUMBER = 274                   /* NUMBER  */
  };
  typedef enum var_expand_parser_tokentype var_expand_parser_token_kind_t;
#endif

/* Value type.  */

/* Location type.  */
#if ! defined VAR_EXPAND_PARSER_LTYPE && ! defined VAR_EXPAND_PARSER_LTYPE_IS_DECLARED
typedef struct VAR_EXPAND_PARSER_LTYPE VAR_EXPAND_PARSER_LTYPE;
struct VAR_EXPAND_PARSER_LTYPE
{
  int first_line;
  int first_column;
  int last_line;
  int last_column;
};
# define VAR_EXPAND_PARSER_LTYPE_IS_DECLARED 1
# define VAR_EXPAND_PARSER_LTYPE_IS_TRIVIAL 1
#endif




int var_expand_parser_parse (struct var_expand_parser_state *state);


#endif /* !YY_VAR_EXPAND_PARSER_VAR_EXPAND_PARSER_H_INCLUDED  */
