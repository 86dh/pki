/* --- BEGIN COPYRIGHT BLOCK ---
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA  02110-1301  USA 
 * 
 * Copyright (C) 2007 Red Hat, Inc.
 * All rights reserved.
 * --- END COPYRIGHT BLOCK ---
 */

#ifndef RA_CLIENT_H
#define RA_CLIENT_H

#ifdef HAVE_CONFIG_H
#ifndef AUTOTOOLS_CONFIG_H
#define AUTOTOOLS_CONFIG_H

/* Eliminate warnings when using Autotools */
#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION

#include <config.h>
#endif /* AUTOTOOLS_CONFIG_H */
#endif /* HAVE_CONFIG_H */

#include "main/NameValueSet.h"
#include "main/RA_Conn.h"
#include "main/RA_Token.h"

class RA_Client
{
  public:
	  RA_Client();
	  ~RA_Client();
  public:
	  int OpHelp(NameValueSet *set);
	  int OpTokenStatus(NameValueSet *set);
	  int OpTokenSet(NameValueSet *set);
	  int OpVarList(NameValueSet *set);
	  int OpVarSet(NameValueSet *set);
	  int OpVarDebug(NameValueSet *set);
	  int OpVarGet(NameValueSet *set);
	  int OpExit(NameValueSet *set);
  public:
	  void Debug(const char *func_name, const char *fmt, ...);
  public:
	  RA_Token m_token;
	  NameValueSet m_vars;
	  PRBool old_style = PR_TRUE;
};

extern "C" int
FormatToken (RA_Client *client, NameValueSet *params, RA_Token *token, RA_Conn *conn);

extern "C" int
ResetPIN (RA_Client *client, NameValueSet *params, RA_Token *token, RA_Conn *conn);

extern "C" int
EnrollToken (RA_Client *client, NameValueSet *params, RA_Token *token, RA_Conn *conn);

#endif /* RA_CLIENT_H */
