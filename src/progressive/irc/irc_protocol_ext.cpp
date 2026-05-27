// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Progressive IRC Server Contributors
//
// IRC Protocol Extensions — Numerics, IRCv3 tags, capabilities, server linking,
// TS6 protocol, UTF-8 support, case mapping, and message enforcement.
//
// Targets RFC 1459 / 2812 / 7194 and IRCv3 specifications.

#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <ctime>
#include <algorithm>
#include <sstream>
#include <mutex>
#include <functional>
#include <cstring>
#include <cstdint>
#include <cctype>
#include <stdexcept>
#include <regex>
#include <array>
#include <iomanip>
#include <optional>
#include <cstdarg>
#include <deque>
#include <chrono>
#include <bitset>

// ---------------------------------------------------------------------------
// progressive::irc namespace
// ---------------------------------------------------------------------------
namespace progressive {
namespace irc {

// ============================================================================
// SECTION 1 : Numeric reply system (RFC 1459, 2812, 7194 + common extensions)
// ============================================================================

// --- 1a. Reply codes --------------------------------------------------------

/// @brief Every standard and widely-used IRC numeric reply.
enum class Numeric : uint16_t {
    // ---- RFC 1459 ----
    RPL_WELCOME           = 001,
    RPL_YOURHOST          = 002,
    RPL_CREATED           = 003,
    RPL_MYINFO            = 004,
    RPL_BOUNCE            = 005,   // also ISUPPORT
    RPL_MAP               = 006,
    RPL_MAPEND            = 007,
    RPL_SNOMASK           = 8,

    // RFC 1459 — trace / stats / links / info
    RPL_TRACELINK         = 200,
    RPL_TRACECONNECTING   = 201,
    RPL_TRACEHANDSHAKE    = 202,
    RPL_TRACEUNKNOWN      = 203,
    RPL_TRACEOPERATOR     = 204,
    RPL_TRACEUSER         = 205,
    RPL_TRACESERVER       = 206,
    RPL_TRACESERVICE      = 207,
    RPL_TRACENEWTYPE      = 208,
    RPL_TRACECLASS        = 209,
    RPL_TRACERECONNECT    = 210,
    RPL_STATSLINKINFO     = 211,
    RPL_STATSCOMMANDS     = 212,
    RPL_STATSCLINE        = 213,
    RPL_STATSNLINE        = 214,
    RPL_STATSILINE        = 215,
    RPL_STATSKLINE        = 216,
    RPL_STATSQLINE        = 217,
    RPL_STATSYLINE        = 218,
    RPL_ENDOFSTATS        = 219,
    RPL_UMODEIS           = 221,
    RPL_SERVLIST          = 234,
    RPL_SERVLISTEND       = 235,
    RPL_STATSLLINE        = 241,
    RPL_STATSUPTIME       = 242,
    RPL_STATSOLINE        = 243,
    RPL_STATSHLINE        = 244,
    RPL_STATSSLINE        = 245,
    RPL_STATSPING         = 246,
    RPL_STATSBLINE        = 247,
    RPL_STATSDLINE        = 250,
    RPL_LUSERCLIENT       = 251,
    RPL_LUSEROP           = 252,
    RPL_LUSERUNKNOWN      = 253,
    RPL_LUSERCHANNELS     = 254,
    RPL_LUSERME           = 255,
    RPL_ADMINME           = 256,
    RPL_ADMINLOC1         = 257,
    RPL_ADMINLOC2         = 258,
    RPL_ADMINEMAIL        = 259,
    RPL_TRACELOG          = 261,
    RPL_TRACEEND          = 262,
    RPL_TRYAGAIN          = 263,
    RPL_LOCALUSERS        = 265,
    RPL_GLOBALUSERS       = 266,

    // RFC 2812 — user / channel / away / who / whois / whowas
    RPL_NONE              = 300,
    RPL_AWAY              = 301,
    RPL_USERHOST          = 302,
    RPL_ISON              = 303,
    RPL_UNAWAY            = 305,
    RPL_NOWAWAY           = 306,
    RPL_WHOISREGNICK      = 307,
    RPL_WHOISUSER         = 311,
    RPL_WHOISSERVER       = 312,
    RPL_WHOISOPERATOR     = 313,
    RPL_WHOWASUSER        = 314,
    RPL_ENDOFWHO          = 315,
    RPL_WHOISCHANOP       = 316,
    RPL_WHOISIDLE         = 317,
    RPL_ENDOFWHOIS        = 318,
    RPL_WHOISCHANNELS     = 319,
    RPL_LISTSTART         = 321,
    RPL_LIST              = 322,
    RPL_LISTEND           = 323,
    RPL_CHANNELMODEIS     = 324,
    RPL_UNIQOPIS          = 325,
    RPL_NOTOPIC           = 331,
    RPL_TOPIC             = 332,
    RPL_TOPICWHOTIME      = 333,
    RPL_INVITELIST        = 336,
    RPL_ENDOFINVITELIST   = 337,
    RPL_WHOISACTUALLY     = 338,
    RPL_INVITING          = 341,
    RPL_SUMMONING         = 342,
    RPL_INVEXLIST         = 346,
    RPL_ENDOFINVEXLIST    = 347,
    RPL_EXCEPTLIST        = 348,
    RPL_ENDOFEXCEPTLIST   = 349,
    RPL_VERSION           = 351,
    RPL_WHOREPLY          = 352,
    RPL_NAMREPLY          = 353,
    RPL_KILLDONE          = 361,
    RPL_CLOSING           = 362,
    RPL_CLOSEEND          = 363,
    RPL_LINKS             = 364,
    RPL_ENDOFLINKS        = 365,
    RPL_ENDOFNAMES        = 366,
    RPL_BANLIST           = 367,
    RPL_ENDOFBANLIST      = 368,
    RPL_ENDOFWHOWAS       = 369,
    RPL_INFO              = 371,
    RPL_MOTD              = 372,
    RPL_INFOSTART         = 373,
    RPL_ENDOFINFO         = 374,
    RPL_MOTDSTART         = 375,
    RPL_ENDOFMOTD         = 376,
    RPL_YOUREOPER         = 381,
    RPL_REHASHING         = 382,
    RPL_YOURESERVICE      = 383,
    RPL_MYPORTIS          = 384,
    RPL_NOTOPERANYMORE    = 385,
    RPL_RSACHALLENGE      = 386,
    RPL_TIME              = 391,
    RPL_USERSSTART        = 392,
    RPL_USERS             = 393,
    RPL_ENDOFUSERS        = 394,
    RPL_NOUSERS           = 395,

    // ---- RFC 2812 ERR_ ----
    ERR_NOSUCHNICK        = 401,
    ERR_NOSUCHSERVER      = 402,
    ERR_NOSUCHCHANNEL     = 403,
    ERR_CANNOTSENDTOCHAN  = 404,
    ERR_TOOMANYCHANNELS   = 405,
    ERR_WASNOSUCHNICK     = 406,
    ERR_TOOMANYTARGETS    = 407,
    ERR_NOSUCHSERVICE     = 408,
    ERR_NOORIGIN          = 409,
    ERR_NORECIPIENT       = 411,
    ERR_NOTEXTTOSEND      = 412,
    ERR_NOTOPLEVEL        = 413,
    ERR_WILDTOPLEVEL      = 414,
    ERR_BADMASK           = 415,
    ERR_UNKNOWNCOMMAND    = 421,
    ERR_NOMOTD            = 422,
    ERR_NOADMININFO       = 423,
    ERR_FILEERROR         = 424,
    ERR_NONICKNAMEGIVEN   = 431,
    ERR_ERRONEUSNICKNAME  = 432,
    ERR_NICKNAMEINUSE     = 433,
    ERR_NICKCOLLISION     = 436,
    ERR_UNAVAILRESOURCE   = 437,
    ERR_USERNOTINCHANNEL  = 441,
    ERR_NOTONCHANNEL      = 442,
    ERR_USERONCHANNEL     = 443,
    ERR_NOLOGIN           = 444,
    ERR_SUMMONDISABLED    = 445,
    ERR_USERSDISABLED     = 446,
    ERR_NOTREGISTERED     = 451,
    ERR_NEEDMOREPARAMS    = 461,
    ERR_ALREADYREGISTERED = 462,
    ERR_NOPERMFORHOST     = 463,
    ERR_PASSWDMISMATCH    = 464,
    ERR_YOUREBANNEDCREEP  = 465,
    ERR_YOUWILLBEBANNED   = 466,
    ERR_KEYSET            = 467,
    ERR_CHANNELISFULL     = 471,
    ERR_UNKNOWNMODE       = 472,
    ERR_INVITEONLYCHAN    = 473,
    ERR_BANNEDFROMCHAN    = 474,
    ERR_BADCHANNELKEY     = 475,
    ERR_BADCHANMASK       = 476,
    ERR_NOCHANMODES       = 477,
    ERR_BANLISTFULL       = 478,
    ERR_NOPRIVILEGES      = 481,
    ERR_CHANOPRIVSNEEDED  = 482,
    ERR_CANTKILLSERVER    = 483,
    ERR_RESTRICTED        = 484,
    ERR_UNIQOPPRIVSNEEDED = 485,
    ERR_NOOPERHOST        = 491,
    ERR_NOSERVICEHOST     = 492,
    ERR_UMODEUNKNOWNFLAG  = 501,
    ERR_USERSDONTMATCH    = 502,

    // ---- RFC 7194 (general additions) ----
    ERR_WHOSYNTAX         = 522,
    ERR_WHOLIMEXCEED      = 523,
    ERR_HELPNOTFOUND      = 524,
    ERR_INVALIDKEY        = 525,
    RPL_STARTTLS          = 670,
    RPL_WHOISSECURE       = 671,
    ERR_STARTTLS          = 691,
    ERR_INVALIDMODEPARAM  = 696,
    RPL_HELPSTART         = 704,
    RPL_HELPTXT           = 705,
    RPL_ENDOFHELP         = 706,
    ERR_NOPRIVS           = 723,
    RPL_LOGGEDIN          = 900,
    RPL_LOGGEDOUT         = 901,
    ERR_NICKLOCKED        = 902,
    RPL_SASLSUCCESS       = 903,
    ERR_SASLFAIL          = 904,
    ERR_SASLTOOLONG       = 905,
    ERR_SASLABORTED       = 906,
    ERR_SASLALREADY       = 907,
    RPL_SASLMECHS         = 908,

    // ---- InspIRCd / Unreal / common extensions ----
    RPL_STATSCLONES       = 274,
    RPL_WHOISCERTFP       = 276,
    RPL_WHOISLOGGEDIN     = 330,   // same as RPL_WHOISACCOUNT
    RPL_WHOISACCOUNT      = 330,
    RPL_WHOISHOST         = 378,
    RPL_WHOISMODES        = 379,
    RPL_WHOISSECRET       = 381,
    RPL_HOSTHIDDEN        = 396,
    ERR_INPUTTOOLONG      = 417,
    ERR_CANTUNLOADMODULE  = 485,
    RPL_SASLAUTHENTICATED = 489,
    ERR_SASLNOTAUTHORIZED  = 489,
    RPL_MAPUSERS           = 271,
    RPL_WHOISSPECIAL       = 320,
    RPL_CHANURL            = 328,
    RPL_CREATIONTIME       = 329,
    RPL_TOPICWHOTIME_ALT  = 333,
    RPL_WHOISACTUALLY_2    = 338,
    RPL_LISTSYNTAX         = 334,
    RPL_WHOISBOT           = 335,
    RPL_ENDOFWHOWAS_2      = 369,
    RPL_RSACHALLENGE2      = 386,
    RPL_VISIBLEHOST        = 396,
    ERR_REDIRECT           = 470,
    ERR_LINKCHANNEL        = 470,
    ERR_OPERONLY           = 481,  // alias
    ERR_NONONREG           = 486,
    ERR_MSGSERVICES        = 487,
    ERR_NOTFORHALFOPS      = 460,
    ERR_TOOMANYMATCHES     = 416,
    ERR_BADCHANNELNAME     = 479,
    ERR_NOULIST            = 480,
    ERR_CANNOTKNOCK        = 480,
    RPL_KNOCK              = 710,
    RPL_KNOCKDLVR          = 711,
    ERR_KNOCKONCHAN        = 712,
    ERR_TOOMANYKNOCK       = 713,
    RPL_QUIETLIST          = 728,
    RPL_ENDOFQUIETLIST     = 729,
    RPL_MONONLINE          = 730,
    RPL_MONOFFLINE         = 731,
    RPL_MONLIST            = 732,
    RPL_ENDOFMONLIST       = 733,
    ERR_MONLISTFULL        = 734,
    RPL_WATCHLIST          = 600,
    RPL_WATCHCLEAR         = 607,
    RPL_NOWON              = 604,
    RPL_NOWOFF             = 605,
    RPL_WATCHOFF           = 602,
    RPL_WATCHSTAT          = 603,
    RPL_LOGOFF             = 601,
    RPL_ISONWATCH          = 606,
    RPL_LISTENTRY          = 322,
    ERR_INVALIDBAN         = 435,
    ERR_BADCHANNAME        = 479,
    ERR_CANNOTCHANGECHANMODE = 477,
};

// --- 1b. Numeric text tables -----------------------------------------------

namespace detail {

struct NumericEntry {
    const char* name;       // symbolic name, e.g. "RPL_WELCOME"
    uint16_t   code;        // numeric value
    const char* format;     // default format string, nullptr = custom
};

/// Complete human-readable table for every numeric defined above.
constexpr NumericEntry kNumericTable[] = {
    // 001 - 009
    {"RPL_WELCOME",           1,   ":Welcome to the %s Internet Relay Chat Network %s"},
    {"RPL_YOURHOST",          2,   ":Your host is %s, running version %s"},
    {"RPL_CREATED",           3,   ":This server was created %s"},
    {"RPL_MYINFO",            4,   "%s %s %s %s"},
    {"RPL_BOUNCE",            5,   "%s :are supported by this server"},
    {"RPL_MAP",               6,   ":%s%-*s :%s"},
    {"RPL_MAPEND",            7,   ":End of /MAP"},
    {"RPL_SNOMASK",           8,   "%s :Server notice mask"},

    // 200s — trace
    {"RPL_TRACELINK",         200, "Link %s%s %s %s"},
    {"RPL_TRACECONNECTING",   201, "Try. %d %s"},
    {"RPL_TRACEHANDSHAKE",    202, "H.S. %d %s"},
    {"RPL_TRACEUNKNOWN",      203, "???? %d %s"},
    {"RPL_TRACEOPERATOR",     204, "Oper %d %s"},
    {"RPL_TRACEUSER",         205, "User %d %s"},
    {"RPL_TRACESERVER",       206, "Serv %d %dS %dC %s %s!%s@%s"},
    {"RPL_TRACESERVICE",      207, "Service %d %s"},
    {"RPL_TRACENEWTYPE",      208, "<newtype> 0 %s"},
    {"RPL_TRACECLASS",        209, "Class %d %d"},
    {"RPL_TRACERECONNECT",    210, nullptr},

    // 211-219 stats
    {"RPL_STATSLINKINFO",     211, "%s %s %u %u %llu %u %u"},
    {"RPL_STATSCOMMANDS",     212, "%s %u %llu"},
    {"RPL_STATSCLINE",        213, "C %s %s %s %d %s"},
    {"RPL_STATSNLINE",        214, "N %s %s %s %d %s"},
    {"RPL_STATSILINE",        215, "I %s %s %s %d %s"},
    {"RPL_STATSKLINE",        216, "K %s %s %s %d %s"},
    {"RPL_STATSQLINE",        217, nullptr},
    {"RPL_STATSYLINE",        218, nullptr},
    {"RPL_ENDOFSTATS",        219, "%c :End of STATS report"},

    // 221-266
    {"RPL_UMODEIS",           221, "%s"},
    {"RPL_SERVLIST",          234, "%s %s %s %s %d %d :%s"},
    {"RPL_SERVLISTEND",       235, "%s %s :End of service listing"},
    {"RPL_STATSLLINE",        241, "L %s %s %s %d %s"},
    {"RPL_STATSUPTIME",       242, ":Server Up %d days %d:%02d:%02d"},
    {"RPL_STATSOLINE",        243, "O %s %s %s %d %s"},
    {"RPL_STATSHLINE",        244, "H %s %s %s %d %s"},
    {"RPL_STATSSLINE",        245, nullptr},
    {"RPL_STATSPING",         246, nullptr},
    {"RPL_STATSBLINE",        247, nullptr},
    {"RPL_STATSDLINE",        250, nullptr},
    {"RPL_LUSERCLIENT",       251, ":There are %d users and %d invisible on %d servers"},
    {"RPL_LUSEROP",           252, "%d :operator(s) online"},
    {"RPL_LUSERUNKNOWN",      253, "%d :unknown connection(s)"},
    {"RPL_LUSERCHANNELS",     254, "%d :channels formed"},
    {"RPL_LUSERME",           255, ":I have %d clients and %d servers"},
    {"RPL_ADMINME",           256, "%s :Administrative info"},
    {"RPL_ADMINLOC1",         257, ":%s"},
    {"RPL_ADMINLOC2",         258, ":%s"},
    {"RPL_ADMINEMAIL",        259, ":%s"},
    {"RPL_TRACELOG",          261, "File %s %d"},
    {"RPL_TRACEEND",          262, "Server %s %s :End of TRACE"},
    {"RPL_TRYAGAIN",          263, "%s :Flooding detected. Please wait %s and try again."},
    {"RPL_LOCALUSERS",        265, "%d %d :Current local users %d, max %d"},
    {"RPL_GLOBALUSERS",       266, "%d %d :Current global users %d, max %d"},
    {"RPL_MAPUSERS",          271, ":%s (%d)"},
    {"RPL_STATSCLONES",       274, nullptr},

    // 276-299
    {"RPL_WHOISCERTFP",       276, "%s :has client certificate fingerprint %s"},

    // 300s
    {"RPL_NONE",              300, nullptr},
    {"RPL_AWAY",              301, "%s :%s"},
    {"RPL_USERHOST",          302, ":%s"},
    {"RPL_ISON",              303, ":%s"},
    {"RPL_UNAWAY",            305, ":You are no longer marked as being away"},
    {"RPL_NOWAWAY",           306, ":You have been marked as being away"},
    {"RPL_WHOISREGNICK",      307, "%s :has identified for this nick"},
    {"RPL_WHOISUSER",         311, "%s %s %s * :%s"},
    {"RPL_WHOISSERVER",       312, "%s %s :%s"},
    {"RPL_WHOISOPERATOR",     313, "%s :is an IRC operator"},
    {"RPL_WHOWASUSER",        314, "%s %s %s * :%s"},
    {"RPL_ENDOFWHO",          315, "%s :End of WHO list"},
    {"RPL_WHOISCHANOP",       316, nullptr},
    {"RPL_WHOISIDLE",         317, "%s %lu %ld :seconds idle, signon time"},
    {"RPL_ENDOFWHOIS",        318, "%s :End of WHOIS list"},
    {"RPL_WHOISCHANNELS",     319, "%s :%s"},
    {"RPL_WHOISSPECIAL",      320, "%s :%s"},
    {"RPL_LISTSTART",         321, "Channel :Users  Name"},
    {"RPL_LIST",              322, "%s %d :%s"},
    {"RPL_LISTEND",           323, ":End of LIST"},
    {"RPL_CHANNELMODEIS",     324, "%s %s %s"},
    {"RPL_UNIQOPIS",          325, "%s %s %s"},
    {"RPL_CHANURL",           328, "%s :%s"},
    {"RPL_CREATIONTIME",      329, "%s %lu"},
    {"RPL_WHOISACCOUNT",      330, "%s %s :is logged in as"},
    {"RPL_NOTOPIC",           331, "%s :No topic is set"},
    {"RPL_TOPIC",             332, "%s :%s"},
    {"RPL_TOPICWHOTIME",      333, "%s %s %lu"},
    {"RPL_LISTSYNTAX",        334, "%s :%s"},
    {"RPL_WHOISBOT",          335, "%s :%s"},
    {"RPL_INVITELIST",        336, "%s %s"},
    {"RPL_ENDOFINVITELIST",   337, "%s :End of channel invite list"},
    {"RPL_WHOISACTUALLY",     338, "%s %s@%s %s :Actual user@host"},
    {"RPL_INVITING",          341, "%s %s"},
    {"RPL_SUMMONING",         342, "%s :User summoned to irc"},
    {"RPL_INVEXLIST",         346, "%s %s"},
    {"RPL_ENDOFINVEXLIST",    347, "%s :End of channel invite exception list"},
    {"RPL_EXCEPTLIST",        348, "%s %s"},
    {"RPL_ENDOFEXCEPTLIST",   349, "%s :End of channel exception list"},
    {"RPL_VERSION",           351, "%s.%s %s :%s"},
    {"RPL_WHOREPLY",          352, "%s %s %s %s %s %s :%d %s"},
    {"RPL_NAMREPLY",          353, "= %s :%s"},
    {"RPL_WHOWASACTUALLY",    354, "%s %s@%s :was actually"},
    {"RPL_KILLDONE",          361, nullptr},
    {"RPL_CLOSING",           362, nullptr},
    {"RPL_CLOSEEND",          363, nullptr},
    {"RPL_LINKS",             364, "%s %s :%d %s"},
    {"RPL_ENDOFLINKS",        365, "%s :End of LINKS list"},
    {"RPL_ENDOFNAMES",        366, "%s :End of NAMES list"},
    {"RPL_BANLIST",           367, "%s %s %s %lu"},
    {"RPL_ENDOFBANLIST",      368, "%s :End of channel ban list"},
    {"RPL_ENDOFWHOWAS",       369, "%s :End of WHOWAS"},
    {"RPL_INFO",              371, ":%s"},
    {"RPL_MOTD",              372, ":- %s"},
    {"RPL_INFOSTART",         373, ":%s"},
    {"RPL_ENDOFINFO",         374, ":End of INFO list"},
    {"RPL_MOTDSTART",         375, ":- %s Message of the day - "},
    {"RPL_ENDOFMOTD",         376, ":End of MOTD command"},
    {"RPL_WHOISHOST",         378, "%s :is connecting from %s@%s %s"},
    {"RPL_WHOISMODES",        379, "%s :is using modes %s"},
    {"RPL_YOUREOPER",         381, ":You are now an IRC operator"},
    {"RPL_REHASHING",         382, "%s :Rehashing"},
    {"RPL_YOURESERVICE",      383, ":You are service %s"},
    {"RPL_MYPORTIS",          384, "%d :Port to local server is"},
    {"RPL_NOTOPERANYMORE",    385, ":You are no longer an IRC operator"},
    {"RPL_RSACHALLENGE",      386, ":%s"},
    {"RPL_TIME",              391, "%s :%s"},
    {"RPL_USERSSTART",        392, ":UserID   Terminal  Host"},
    {"RPL_USERS",             393, ":%-8s %-9s %-8s"},
    {"RPL_ENDOFUSERS",        394, ":End of users"},
    {"RPL_NOUSERS",           395, ":Nobody logged in"},
    {"RPL_HOSTHIDDEN",        396, "%s :is now your hidden host"},
    {"RPL_VISIBLEHOST",       396, nullptr},

    // 400s errors
    {"ERR_NOSUCHNICK",        401, "%s :No such nick/channel"},
    {"ERR_NOSUCHSERVER",      402, "%s :No such server"},
    {"ERR_NOSUCHCHANNEL",     403, "%s :No such channel"},
    {"ERR_CANNOTSENDTOCHAN",  404, "%s :Cannot send to channel"},
    {"ERR_TOOMANYCHANNELS",   405, "%s :You have joined too many channels"},
    {"ERR_WASNOSUCHNICK",     406, "%s :There was no such nickname"},
    {"ERR_TOOMANYTARGETS",    407, "%s :%d recipients. %s"},
    {"ERR_NOSUCHSERVICE",     408, "%s :No such service"},
    {"ERR_NOORIGIN",          409, ":No origin specified"},
    {"ERR_NORECIPIENT",       411, ":No recipient given (%s)"},
    {"ERR_NOTEXTTOSEND",      412, ":No text to send"},
    {"ERR_NOTOPLEVEL",        413, "%s :No toplevel domain specified"},
    {"ERR_WILDTOPLEVEL",      414, "%s :Wildcard in toplevel domain"},
    {"ERR_BADMASK",           415, "%s :Bad Server/host mask"},
    {"ERR_TOOMANYMATCHES",    416, "%s :Too many matches"},
    {"ERR_INPUTTOOLONG",      417, "%s :Input line was too long"},
    {"ERR_UNKNOWNCOMMAND",    421, "%s :Unknown command"},
    {"ERR_NOMOTD",            422, ":MOTD File is missing"},
    {"ERR_NOADMININFO",       423, "%s :No administrative info available"},
    {"ERR_FILEERROR",         424, ":File error doing %s on %s"},
    {"ERR_NONICKNAMEGIVEN",   431, ":No nickname given"},
    {"ERR_ERRONEUSNICKNAME",  432, "%s :Erroneous nickname"},
    {"ERR_NICKNAMEINUSE",     433, "%s :Nickname is already in use"},
    {"ERR_NICKCOLLISION",     436, "%s :Nickname collision KILL from %s@%s"},
    {"ERR_UNAVAILRESOURCE",   437, "%s :Nick/channel is temporarily unavailable"},
    {"ERR_USERNOTINCHANNEL",  441, "%s %s :They aren't on that channel"},
    {"ERR_NOTONCHANNEL",      442, "%s :You're not on that channel"},
    {"ERR_USERONCHANNEL",     443, "%s %s :is already on channel"},
    {"ERR_NOLOGIN",           444, "%s :User not logged in"},
    {"ERR_SUMMONDISABLED",    445, ":SUMMON has been disabled"},
    {"ERR_USERSDISABLED",     446, ":USERS has been disabled"},
    {"ERR_NOTREGISTERED",     451, ":You have not registered"},
    {"ERR_NEEDMOREPARAMS",    461, "%s :Not enough parameters"},
    {"ERR_ALREADYREGISTERED", 462, ":Unauthorized command (already registered)"},
    {"ERR_NOPERMFORHOST",     463, ":Your host isn't among the privileged"},
    {"ERR_PASSWDMISMATCH",    464, ":Password incorrect"},
    {"ERR_YOUREBANNEDCREEP",  465, ":You are banned from this server"},
    {"ERR_YOUWILLBEBANNED",   466, nullptr},
    {"ERR_KEYSET",            467, "%s :Channel key already set"},
    {"ERR_REDIRECT",          470, "%s %s :You have been redirected"},
    {"ERR_CHANNELISFULL",     471, "%s :Cannot join channel (+l)"},
    {"ERR_UNKNOWNMODE",       472, "%c :is unknown mode char to me"},
    {"ERR_INVITEONLYCHAN",    473, "%s :Cannot join channel (+i)"},
    {"ERR_BANNEDFROMCHAN",    474, "%s :Cannot join channel (+b)"},
    {"ERR_BADCHANNELKEY",     475, "%s :Cannot join channel (+k)"},
    {"ERR_BADCHANMASK",       476, "%s :Bad Channel Mask"},
    {"ERR_CANNOTCHANGECHANMODE", 477, "%s :Channel doesn't support modes"},
    {"ERR_BANLISTFULL",       478, "%s %s :Channel ban/except list is full"},
    {"ERR_BADCHANNELNAME",    479, "%s :Illegal channel name"},
    {"ERR_NOPRIVILEGES",      481, ":Permission Denied- You do not have the correct IRC operator privileges"},
    {"ERR_CHANOPRIVSNEEDED",  482, "%s :You're not channel operator"},
    {"ERR_CANTKILLSERVER",    483, ":You can't kill a server!"},
    {"ERR_RESTRICTED",        484, ":Your connection is restricted!"},
    {"ERR_NOOPERHOST",        491, ":No O-lines for your host"},
    {"ERR_NOSERVICEHOST",     492, nullptr},
    {"ERR_UMODEUNKNOWNFLAG",  501, ":Unknown MODE flag"},
    {"ERR_USERSDONTMATCH",    502, ":Cannot change mode for other users"},

    // 520s
    {"ERR_WHOSYNTAX",         522, nullptr},
    {"ERR_WHOLIMEXCEED",      523, nullptr},
    {"ERR_HELPNOTFOUND",      524, "%s :No help available on this topic"},
    {"ERR_INVALIDKEY",        525, "%s :Key is not well-formed"},

    // 600s - watch / monitor
    {"RPL_WATCHLIST",         600, "%s %s %s %ld :%s"},
    {"RPL_LOGOFF",            601, "%s %s %s %ld :%s"},
    {"RPL_WATCHOFF",          602, "%s %s %s %ld :%s"},
    {"RPL_WATCHSTAT",         603, "%s %s %s %ld :%s"},
    {"RPL_NOWON",             604, "%s %s %s %ld :%s"},
    {"RPL_NOWOFF",            605, "%s %s %s %ld :%s"},
    {"RPL_ISONWATCH",         606, "%s :%s"},
    {"RPL_WATCHCLEAR",        607, ":End of WATCH"},
    {"RPL_STARTTLS",          670, ":STARTTLS successful, proceed with TLS handshake"},
    {"RPL_WHOISSECURE",       671, "%s :is using a secure connection"},
    {"ERR_STARTTLS",          691, ":STARTTLS failed"},
    {"ERR_INVALIDMODEPARAM",  696, "%s %s %s :%s"},

    // 700s
    {"RPL_HELPSTART",         704, "%s :%s"},
    {"RPL_HELPTXT",           705, "%s :%s"},
    {"RPL_ENDOFHELP",         706, "%s :End of help"},
    {"RPL_KNOCK",             710, "%s %s!%s@%s :has asked for an invite"},
    {"RPL_KNOCKDLVR",         711, "%s %s :Your KNOCK has been delivered"},
    {"ERR_KNOCKONCHAN",       712, "%s :You are already on that channel"},
    {"ERR_TOOMANYKNOCK",      713, "%s :Too many KNOCKs"},
    {"ERR_NOPRIVS",           723, "%s :Insufficient oper privileges"},
    {"RPL_QUIETLIST",         728, "%s %s %s %lu"},
    {"RPL_ENDOFQUIETLIST",    729, "%s :End of channel quiet list"},
    {"RPL_MONONLINE",         730, ":%s"},
    {"RPL_MONOFFLINE",        731, ":%s"},
    {"RPL_MONLIST",           732, ":%s"},
    {"RPL_ENDOFMONLIST",      733, ":End of MONITOR list"},
    {"ERR_MONLISTFULL",       734, "%d %s :Monitor list is full"},

    // 900s - SASL
    {"RPL_LOGGEDIN",          900, "%s!%s@%s %s :You are now logged in as %s"},
    {"RPL_LOGGEDOUT",         901, "%s!%s@%s :You are now logged out"},
    {"ERR_NICKLOCKED",        902, ":You must use a nick assigned to you"},
    {"RPL_SASLSUCCESS",       903, ":SASL authentication successful"},
    {"ERR_SASLFAIL",          904, ":SASL authentication failed"},
    {"ERR_SASLTOOLONG",       905, ":SASL message too long"},
    {"ERR_SASLABORTED",       906, ":SASL authentication aborted"},
    {"ERR_SASLALREADY",       907, ":You are already authenticated using SASL"},
    {"RPL_SASLMECHS",         908, "%s :are available SASL mechanisms"},
};

constexpr size_t kNumericTableSize = sizeof(kNumericTable) / sizeof(kNumericTable[0]);

} // namespace detail

/// @brief Look up a numeric's symbolic name.
inline const char* numeric_name(uint16_t code) {
    for (size_t i = 0; i < detail::kNumericTableSize; ++i) {
        if (detail::kNumericTable[i].code == code)
            return detail::kNumericTable[i].name;
    }
    return nullptr;
}

/// @brief Look up a numeric's default format string.
inline const char* numeric_format(uint16_t code) {
    for (size_t i = 0; i < detail::kNumericTableSize; ++i) {
        if (detail::kNumericTable[i].code == code)
            return detail::kNumericTable[i].format;
    }
    return nullptr;
}

/// @brief Determine if a numeric is an error (4xx/5xx/6xx/7xx/9xx).
inline bool numeric_is_error(uint16_t code) {
    return (code >= 400 && code <= 599) ||
           (code >= 691 && code <= 699) ||
           (code >= 723 && code <= 724) ||
           (code >= 902 && code <= 907);
}

// ============================================================================
// SECTION 2 : IRCv3 Message Tags — encoding, escaping, parsing
// ============================================================================

/// @brief Tag value escaping per IRCv3.2 (message-tags).
///
/// Escaped characters:   ;  \  \r  \n  SPACE
/// Escape sequences:     \;  \\  \r  \n  \s
///
/// Vendor-only keys may be absent from the client-facing tag map, but all tags
/// are stored in the raw representation so the server can relay them faithfully
/// to other servers.
namespace tag_util {

/// Unescape one tag value.  Returns the unescaped string.
inline std::string unescape_value(const std::string& raw, size_t start, size_t len) {
    std::string out;
    out.reserve(len);
    for (size_t i = start; i < start + len; ++i) {
        if (raw[i] == '\\' && i + 1 < start + len) {
            switch (raw[i + 1]) {
                case ':':  out.push_back(';');   break;
                case 's':  out.push_back(' ');   break;
                case 'r':  out.push_back('\r');  break;
                case 'n':  out.push_back('\n');  break;
                case '\\': out.push_back('\\');  break;
                default:   out.push_back(raw[i + 1]); break; // unknown escape → literal
            }
            ++i;  // consumed the escaped character
        } else {
            out.push_back(raw[i]);
        }
    }
    return out;
}

/// Escape one tag value for wire format.
inline std::string escape_value(const std::string& input) {
    std::string out;
    out.reserve(input.size() + 8);   // slight slack for escapes
    for (char ch : input) {
        switch (ch) {
            case ';':  out += "\\:"; break;
            case ' ':  out += "\\s"; break;
            case '\\': out += "\\\\"; break;
            case '\r': out += "\\r"; break;
            case '\n': out += "\\n"; break;
            default:   out.push_back(ch);
        }
    }
    return out;
}

/// Validate that a tag key is legal (ASCII alphanumeric, '-', '.', '/').
inline bool valid_key_char(char c) {
    return (c >= 'A' && c <= 'Z') ||
           (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') ||
           c == '-' || c == '.' || c == '/';
}

inline bool valid_key(const std::string& key) {
    if (key.empty()) return false;
    // Vendor prefix is optional, but if present must contain '/'
    for (char c : key) {
        if (!valid_key_char(c)) return false;
    }
    // Must have client-only separator check: a '/' must not be first char
    if (key[0] == '/') return false;
    return true;
}

/// A single parsed tag: key + optional value.
struct ParsedTag {
    std::string key;
    std::string value;
    bool has_value = false;  // True if '=' was present (even if value empty)
};

} // namespace tag_util

/// @brief Parser and holder for IRCv3 message tags (the leading @-prefixed
///        block on an IRC message line).
class MessageTags {
public:
    MessageTags() = default;

    /// Parse tags from the raw string that follows the leading '@'.
    /// Returns the number of tags successfully parsed.
    /// The input is everything after '@' up to the first space (exclusive).
    int parse(const std::string& raw_tags) {
        clear();
        if (raw_tags.empty()) return 0;

        size_t pos = 0;
        const size_t len = raw_tags.size();

        while (pos < len) {
            // Read key
            size_t key_start = pos;
            while (pos < len && raw_tags[pos] != '=' && raw_tags[pos] != ';') {
                ++pos;
            }
            std::string key(raw_tags, key_start, pos - key_start);
            if (!tag_util::valid_key(key)) {
                // Invalid key: skip to next ';'
                while (pos < len && raw_tags[pos] != ';') ++pos;
                if (pos < len) ++pos;
                continue;
            }

            std::string value;
            bool has_val = false;

            if (pos < len && raw_tags[pos] == '=') {
                has_val = true;
                ++pos; // skip '='
                size_t val_start = pos;
                // Value runs until unescaped ';' or NUL
                while (pos < len) {
                    if (raw_tags[pos] == '\\' && pos + 1 < len) {
                        pos += 2; // skip escaped char
                        continue;
                    }
                    if (raw_tags[pos] == ';') break;
                    ++pos;
                }
                value = tag_util::unescape_value(raw_tags, val_start, pos - val_start);
            }

            tag_util::ParsedTag pt;
            pt.key       = std::move(key);
            pt.value     = std::move(value);
            pt.has_value = has_val;
            tags_.push_back(std::move(pt));

            // Advance past ';' separator
            if (pos < len && raw_tags[pos] == ';') ++pos;
        }

        return static_cast<int>(tags_.size());
    }

    /// Serialize all tags back to the wire format (without the leading '@').
    std::string serialize() const {
        if (tags_.empty()) return {};
        std::ostringstream oss;
        for (size_t i = 0; i < tags_.size(); ++i) {
            if (i > 0) oss << ';';
            oss << tags_[i].key;
            if (tags_[i].has_value) {
                oss << '=' << tag_util::escape_value(tags_[i].value);
            }
        }
        return oss.str();
    }

    /// Get a tag value by key.  Returns nullptr if absent.
    const std::string* get(const std::string& key) const {
        for (auto& t : tags_) {
            if (t.key == key) return t.has_value ? &t.value : &empty_val_;
        }
        return nullptr;
    }

    /// Check if a tag exists (even without value).
    bool has(const std::string& key) const {
        for (auto& t : tags_) {
            if (t.key == key) return true;
        }
        return false;
    }

    /// Set or add a tag.
    void set(const std::string& key, const std::string& value, bool has_value = true) {
        for (auto& t : tags_) {
            if (t.key == key) {
                t.value     = value;
                t.has_value = has_value;
                return;
            }
        }
        tag_util::ParsedTag pt;
        pt.key       = key;
        pt.value     = value;
        pt.has_value = has_value;
        tags_.push_back(std::move(pt));
    }

    /// Remove a tag.
    void remove(const std::string& key) {
        tags_.erase(
            std::remove_if(tags_.begin(), tags_.end(),
                           [&](const tag_util::ParsedTag& t) { return t.key == key; }),
            tags_.end());
    }

    /// Remove all tags.
    void clear() { tags_.clear(); }

    /// Number of tags.
    size_t size() const { return tags_.size(); }

    /// Iterate all tags.
    const std::vector<tag_util::ParsedTag>& all() const { return tags_; }

    /// Get wire-format length of the full @-prefixed tag block.
    size_t wire_length() const {
        std::string s = serialize();
        return s.empty() ? 0 : s.size() + 1; // +1 for leading '@'
    }

private:
    std::vector<tag_util::ParsedTag> tags_;
    std::string empty_val_;  // Return ref for valueless tag lookups
};

// ============================================================================
// SECTION 3 : IRCv3 Capability negotiation
// ============================================================================

/// @brief Canonical list of IRCv3 capabilities.
enum class Capability : uint32_t {
    kMessageTags      = 0,    // message-tags
    kServerTime       = 1,    // server-time
    kAccountTag       = 2,    // account-tag
    kAccountNotify    = 3,    // account-notify
    kAwayNotify       = 4,    // away-notify
    kChgHost          = 5,    // chghost
    kEchoMessage      = 6,    // echo-message
    kExtendedJoin     = 7,    // extended-join
    kInviteNotify     = 8,    // invite-notify
    kMultiPrefix      = 9,    // multi-prefix
    kSasl             = 10,   // sasl
    kSetName          = 11,   // setname
    kUserhostInNames  = 12,   // userhost-in-names
    kBatch            = 13,   // batch
    kLabeledResponse  = 14,   // labeled-response
    kCapNotify        = 15,   // cap-notify
    kSts              = 16,   // sts
    kChgHost2         = 17,   // alias for chghost
    kAckRequired      = 18,   // cap-notify signalling
    kMaxCount
};

/// @brief String representation for each capability.
constexpr const char* kCapabilityNames[] = {
    "message-tags",
    "server-time",
    "account-tag",
    "account-notify",
    "away-notify",
    "chghost",
    "echo-message",
    "extended-join",
    "invite-notify",
    "multi-prefix",
    "sasl",
    "setname",
    "userhost-in-names",
    "batch",
    "labeled-response",
    "cap-notify",
    "sts",
    "chghost",
    "cap-notify",
    "",              // kMaxCount placeholder
};

static_assert(sizeof(kCapabilityNames) / sizeof(kCapabilityNames[0]) ==
              static_cast<size_t>(Capability::kMaxCount) + 1,
              "Capability name table size mismatch");

/// @brief Capability manager — tracks caps per connection.
class CapManager {
public:
    CapManager() { reset(); }

    void reset() {
        caps_.reset();
        pending_.clear();
    }

    /// Enable a capability (local state).
    void enable(Capability cap) {
        auto idx = static_cast<size_t>(cap);
        if (idx < caps_.size()) caps_.set(idx);
    }

    /// Disable a capability.
    void disable(Capability cap) {
        auto idx = static_cast<size_t>(cap);
        if (idx < caps_.size()) caps_.reset(idx);
    }

    /// Check if a capability is enabled.
    bool has(Capability cap) const {
        auto idx = static_cast<size_t>(cap);
        return idx < caps_.size() && caps_.test(idx);
    }

    /// Request a pending capability negotiation (CAP REQ).
    void add_pending(const std::string& cap_name) {
        pending_.push_back(cap_name);
    }

    /// Clear pending requests.
    void clear_pending() { pending_.clear(); }

    const std::vector<std::string>& pending() const { return pending_; }

    /// Look up a Capability enum from its string name.
    static std::optional<Capability> from_string(const std::string& name) {
        for (size_t i = 0; i <= static_cast<size_t>(Capability::kMaxCount); ++i) {
            if (name == kCapabilityNames[i])
                return static_cast<Capability>(i);
        }
        return std::nullopt;
    }

    /// Return the string for a Capability.
    static const char* to_string(Capability cap) {
        auto idx = static_cast<size_t>(cap);
        if (idx <= static_cast<size_t>(Capability::kMaxCount))
            return kCapabilityNames[idx];
        return nullptr;
    }

    /// Get the full "CAP LS 302" list string.
    std::string cap_list() const {
        std::ostringstream oss;
        bool first = true;
        for (size_t i = 0; i <= static_cast<size_t>(Capability::kMaxCount); ++i) {
            // Skip duplicate aliases
            if (i == static_cast<size_t>(Capability::kChgHost2)) continue;
            if (i == static_cast<size_t>(Capability::kAckRequired)) continue;

            if (!first) oss << ' ';
            oss << kCapabilityNames[i];
            first = false;
        }
        return oss.str();
    }

private:
    std::bitset<static_cast<size_t>(Capability::kMaxCount) + 1> caps_;
    std::vector<std::string> pending_;
};

// ============================================================================
// SECTION 4 : Server-time timestamps (IRCv3 server-time)
// ============================================================================

/// @brief Generate an ISO 8601 timestamp as required by server-time.
///        Format: YYYY-MM-DDTHH:MM:SS.sssZ
inline std::string server_time_now() {
    using namespace std::chrono;
    auto now = system_clock::now();
    auto t    = system_clock::to_time_t(now);
    auto ms   = duration_cast<milliseconds>(now.time_since_epoch()) % 1000;

    struct tm tm_buf;
    gmtime_r(&t, &tm_buf);

    char buf[32];
    int n = snprintf(buf, sizeof(buf),
                     "%04d-%02d-%02dT%02d:%02d:%02d.%03lldZ",
                     tm_buf.tm_year + 1900,
                     tm_buf.tm_mon + 1,
                     tm_buf.tm_mday,
                     tm_buf.tm_hour,
                     tm_buf.tm_min,
                     tm_buf.tm_sec,
                     static_cast<long long>(ms.count()));
    if (n < 0 || static_cast<size_t>(n) >= sizeof(buf)) return {};
    return std::string(buf, static_cast<size_t>(n));
}

/// @brief Parse a server-time ISO 8601 string into a time_t + milliseconds.
inline bool parse_server_time(const std::string& ts, time_t* out_sec, int* out_ms) {
    struct tm tm_buf = {};
    int ms = 0;
    // Expected: YYYY-MM-DDTHH:MM:SS.sssZ
    int n = sscanf(ts.c_str(), "%d-%d-%dT%d:%d:%d.%dZ",
                   &tm_buf.tm_year, &tm_buf.tm_mon, &tm_buf.tm_mday,
                   &tm_buf.tm_hour, &tm_buf.tm_min, &tm_buf.tm_sec, &ms);
    if (n < 6) {
        // Try without ms
        n = sscanf(ts.c_str(), "%d-%d-%dT%d:%d:%dZ",
                   &tm_buf.tm_year, &tm_buf.tm_mon, &tm_buf.tm_mday,
                   &tm_buf.tm_hour, &tm_buf.tm_min, &tm_buf.tm_sec);
        if (n < 6) return false;
        ms = 0;
    }
    tm_buf.tm_year -= 1900;
    tm_buf.tm_mon  -= 1;
    tm_buf.tm_isdst = 0;

    *out_sec = timegm(&tm_buf);
    *out_ms  = ms;
    return true;
}

// ============================================================================
// SECTION 5 : Batch message handling (IRCv3 batch)
// ============================================================================

/// @brief Tracks an active batch session.
struct BatchSession {
    std::string              batch_type;   // e.g. "netsplit", "chathistory"
    std::string              batch_tag;    // unique identifier
    std::vector<std::string> params;       // additional reference types
    time_t                   start_time = 0;
    int                      message_count = 0;
    bool                     open = true;
};

/// @brief Batch manager — handles BATCH +type ... / BATCH -type sequences.
class BatchManager {
public:
    BatchManager() = default;

    /// Open a new batch.  Returns false if the tag is already in use.
    bool open(const std::string& tag, const std::string& batch_type,
              const std::vector<std::string>& params = {}) {
        if (sessions_.find(tag) != sessions_.end()) return false;

        BatchSession sess;
        sess.batch_type = batch_type;
        sess.batch_tag  = tag;
        sess.params     = params;
        sess.start_time = std::time(nullptr);
        sess.open       = true;
        sessions_[tag]  = std::move(sess);
        return true;
    }

    /// Close a batch.  Returns the session so the caller can flush.
    std::optional<BatchSession> close(const std::string& tag) {
        auto it = sessions_.find(tag);
        if (it == sessions_.end() || !it->second.open) return std::nullopt;
        it->second.open = false;
        BatchSession result = std::move(it->second);
        sessions_.erase(it);
        return result;
    }

    /// Check if a batch tag is currently open.
    bool is_open(const std::string& tag) const {
        auto it = sessions_.find(tag);
        return it != sessions_.end() && it->second.open;
    }

    /// Get a batch session by tag (returns nullptr if absent).
    const BatchSession* get(const std::string& tag) const {
        auto it = sessions_.find(tag);
        return (it != sessions_.end()) ? &it->second : nullptr;
    }

    /// Increment the message counter for an open batch.
    void increment(const std::string& tag) {
        auto it = sessions_.find(tag);
        if (it != sessions_.end()) ++it->second.message_count;
    }

    /// Remove all batches (e.g. on disconnect).
    void clear() { sessions_.clear(); }

    /// Number of active batches.
    size_t count() const { return sessions_.size(); }

private:
    std::unordered_map<std::string, BatchSession> sessions_;
};

/// @brief Build a "BATCH +ref type params" open message.
inline std::string batch_open_message(const std::string& ref, const std::string& type,
                                      const std::vector<std::string>& params = {}) {
    std::ostringstream oss;
    oss << "BATCH +" << ref << ' ' << type;
    for (auto& p : params) oss << ' ' << p;
    return oss.str();
}

/// @brief Build a "BATCH -ref" close message.
inline std::string batch_close_message(const std::string& ref) {
    std::ostringstream oss;
    oss << "BATCH -" << ref;
    return oss.str();
}

// ============================================================================
// SECTION 6 : Labeled response (IRCv3 labeled-response)
// ============================================================================

/// @brief Generate a labeled response wrapper.
///        Appends a "label" tag to a response message so that the client can
///        correlate it with its originating command.
inline std::string labeled_response(MessageTags& tags, const std::string& label,
                                    const std::string& server_name,
                                    const std::string& command,
                                    const std::string& params) {
    // Clone tags and add/override the label
    MessageTags out_tags = tags;
    out_tags.set("label", label);

    std::ostringstream oss;
    std::string tag_block = out_tags.serialize();
    if (!tag_block.empty()) oss << '@' << tag_block << ' ';
    oss << ':' << server_name << ' ' << command << ' ' << params;
    return oss.str();
}

/// @brief Echo a command back to the client with a label (echo-message cap).
inline std::string echo_message(const std::string& label, const std::string& server_name,
                                const std::string& source_nick,
                                const std::string& source_user,
                                const std::string& source_host,
                                const std::string& command,
                                const std::string& trailing) {
    MessageTags tags;
    tags.set("label", label);
    tags.set("time", server_time_now());

    std::ostringstream oss;
    std::string tag_block = tags.serialize();
    if (!tag_block.empty()) oss << '@' << tag_block << ' ';
    oss << ':' << source_nick << '!' << source_user << '@' << source_host
        << ' ' << command << ' ' << trailing;
    return oss.str();
}

// ============================================================================
// SECTION 7 : IRCv3 notifications — ACCOUNT, AWAY, CHGHOST, SETNAME
// ============================================================================

/// @brief Build an ACCOUNT notification message.
///        :nick!user@host ACCOUNT accountname
inline std::string account_notify(const std::string& nick, const std::string& user,
                                  const std::string& host, const std::string& account) {
    std::ostringstream oss;
    oss << ':' << nick << '!' << user << '@' << host << " ACCOUNT " << account;
    return oss.str();
}

/// @brief Build an AWAY notification broadcast.
///        :nick!user@host AWAY :message   (setting away)
///        :nick!user@host AWAY            (unsetting away)
inline std::string away_notify(const std::string& nick, const std::string& user,
                               const std::string& host, const std::string& away_msg) {
    std::ostringstream oss;
    oss << ':' << nick << '!' << user << '@' << host << " AWAY";
    if (!away_msg.empty()) oss << " :" << away_msg;
    return oss.str();
}

/// @brief Build a CHGHOST notification.
///        :nick!olduser@oldhost CHGHOST newuser newhost
inline std::string chghost_notify(const std::string& nick,
                                  const std::string& old_user, const std::string& old_host,
                                  const std::string& new_user, const std::string& new_host) {
    std::ostringstream oss;
    oss << ':' << nick << '!' << old_user << '@' << old_host
        << " CHGHOST " << new_user << ' ' << new_host;
    return oss.str();
}

/// @brief Build a SETNAME notification.
///        :nick!user@host SETNAME :new real name
inline std::string setname_notify(const std::string& nick, const std::string& user,
                                  const std::string& host, const std::string& realname) {
    std::ostringstream oss;
    oss << ':' << nick << '!' << user << '@' << host << " SETNAME :" << realname;
    return oss.str();
}

// ============================================================================
// SECTION 8 : Extended JOIN (IRCv3 extended-join)
// ============================================================================

/// @brief Build an extended JOIN message.
///        :nick!user@host JOIN #channel account :realname
inline std::string extended_join(const std::string& nick, const std::string& user,
                                 const std::string& host, const std::string& channel,
                                 const std::string& account, const std::string& realname) {
    std::ostringstream oss;
    oss << ':' << nick << '!' << user << '@' << host
        << " JOIN " << channel << ' ' << account << " :" << realname;
    return oss.str();
}

// ============================================================================
// SECTION 9 : Multi-prefix (IRCv3 multi-prefix)
// ============================================================================

/// @brief Prefix characters in order of rank (highest first).
constexpr const char* kChannelPrefixes = "~&@%+";
/// @brief Corresponding prefix mode letters.
constexpr const char* kPrefixModes     = "qaohv";

/// @brief Given a mode character ('q','a','o','h','v'), return the prefix.
inline char prefix_for_mode(char mode) {
    const char* p = strchr(kPrefixModes, mode);
    return p ? kChannelPrefixes[p - kPrefixModes] : '\0';
}

/// @brief Given a prefix character, return the mode letter.
inline char mode_for_prefix(char prefix) {
    const char* p = strchr(kChannelPrefixes, prefix);
    return p ? kPrefixModes[p - kChannelPrefixes] : '\0';
}

/// @brief Build a NAMES entry with multi-prefix.
///        @+nick  for op+voice, etc.
inline std::string multi_prefix_nick(const std::string& prefixes, const std::string& nick) {
    return prefixes + nick;
}

// ============================================================================
// SECTION 10 : Message tag helpers for account-tag, server-time
// ============================================================================

/// @brief Append an account tag (account=name) to the message tags.
inline void tag_account(MessageTags& tags, const std::string& account) {
    if (!account.empty()) tags.set("account", account);
}

/// @brief Append a server-time tag (time=...) to the message tags.
inline void tag_server_time(MessageTags& tags) {
    tags.set("time", server_time_now());
}

/// @brief Build a full tag block string including account and time.
inline std::string build_tag_block(const std::string& account, bool include_time) {
    MessageTags tags;
    if (!account.empty()) tags.set("account", account);
    if (include_time)    tags.set("time", server_time_now());
    std::string s = tags.serialize();
    return s.empty() ? "" : "@" + s + " ";
}

// ============================================================================
// SECTION 11 : CASEMAPPING — ascii, rfc1459, strict-rfc1459
// ============================================================================

/// @brief Supported case-mapping strategies.
enum class CaseMapping : uint8_t {
    kAscii         = 0,  // only A-Z → a-z
    kRfc1459       = 1,  // A-Z → a-z, {|} → [\]
    kStrictRfc1459 = 2,  // A-Z → a-z, {|}~ → [\]^  (strict = includes '~'->'^')
};

/// @brief Case-folding table per mapping.
class CaseMapTable {
public:
    explicit CaseMapTable(CaseMapping mapping) : mapping_(mapping) { build(); }

    /// Fold a single character.
    char fold(char c) const {
        unsigned char uc = static_cast<unsigned char>(c);
        return static_cast<char>(fold_tbl_[uc]);
    }

    /// Fold an entire string in place.
    void fold_inplace(std::string& s) const {
        for (auto& c : s) {
            unsigned char uc = static_cast<unsigned char>(c);
            c = static_cast<char>(fold_tbl_[uc]);
        }
    }

    /// Return a folded copy.
    std::string folded(const std::string& s) const {
        std::string out = s;
        fold_inplace(out);
        return out;
    }

    /// Case-insensitive compare.
    bool equals(const std::string& a, const std::string& b) const {
        return folded(a) == folded(b);
    }

    /// Case-insensitive hash (using folded key).
    struct Hash {
        const CaseMapTable* tbl;
        Hash(const CaseMapTable* t = nullptr) : tbl(t) {}
        size_t operator()(const std::string& s) const {
            return std::hash<std::string>{}(tbl ? tbl->folded(s) : s);
        }
    };

    /// Case-insensitive equality for unordered containers.
    struct Equal {
        const CaseMapTable* tbl;
        Equal(const CaseMapTable* t = nullptr) : tbl(t) {}
        bool operator()(const std::string& a, const std::string& b) const {
            return tbl ? tbl->equals(a, b) : (a == b);
        }
    };

private:
    CaseMapping mapping_;
    uint8_t fold_tbl_[256] = {};

    void build() {
        // Identity mapping for all bytes
        for (int i = 0; i < 256; ++i) fold_tbl_[i] = static_cast<uint8_t>(i);

        // Always fold A-Z → a-z
        for (int i = 'A'; i <= 'Z'; ++i)
            fold_tbl_[i] = static_cast<uint8_t>(i + ('a' - 'A'));

        if (mapping_ == CaseMapping::kAscii) return;

        // RFC 1459 folds:   {|} → [\]
        fold_tbl_['{'] = '[';
        fold_tbl_['}'] = '\\';
        fold_tbl_['|'] = '\\';

        if (mapping_ == CaseMapping::kStrictRfc1459) {
            // strict-rfc1459 also folds  ~ → ^
            fold_tbl_['~'] = '^';
        }

        // Also fold lowercase versions of the special chars back to the target
        // so that the mapping is symmetric:  [ → [  and  { → [
        // (the lower-case variant is the canonical one)
        fold_tbl_['['] = '[';  // already is [ → stays
        fold_tbl_['\\'] = '\\';
        if (mapping_ == CaseMapping::kStrictRfc1459) {
            fold_tbl_['^'] = '^';
        }
    }
};

/// @brief Registry of common case-map tables.
class CaseMapRegistry {
public:
    static CaseMapRegistry& instance() {
        static CaseMapRegistry reg;
        return reg;
    }

    const CaseMapTable& get(CaseMapping m) {
        auto it = tables_.find(m);
        if (it != tables_.end()) return *it->second;
        auto ins = tables_.emplace(m, std::make_unique<CaseMapTable>(m));
        return *ins.first->second;
    }

    const CaseMapTable& by_name(const std::string& name) {
        if (name == "ascii")            return get(CaseMapping::kAscii);
        if (name == "rfc1459")          return get(CaseMapping::kRfc1459);
        if (name == "strict-rfc1459")   return get(CaseMapping::kStrictRfc1459);
        // default
        return get(CaseMapping::kRfc1459);
    }

    /// Return the ISUPPORT CASEMAPPING value string.
    static const char* to_isupport(CaseMapping m) {
        switch (m) {
            case CaseMapping::kAscii:          return "ascii";
            case CaseMapping::kRfc1459:        return "rfc1459";
            case CaseMapping::kStrictRfc1459:  return "strict-rfc1459";
        }
        return "rfc1459";
    }

private:
    std::unordered_map<CaseMapping, std::unique_ptr<CaseMapTable>> tables_;
    CaseMapRegistry() = default;
};

// ============================================================================
// SECTION 12 : CHANMODES definitions
// ============================================================================

/// @brief CHANMODES categories per RFC 2812 / IRCv3.
///
/// Categories are four groups (A,B,C,D) separated by commas:
///   A = Modes that add/remove a nick or address from a list (e.g. +b/+e/+I)
///   B = Modes that require a parameter and are always set/unset (e.g. +k)
///   C = Modes that only require a parameter when set (e.g. +l)
///   D = Modes that never take a parameter (e.g. +imnpst)
///
/// The resulting ISUPPORT token looks like:
///   CHANMODES=beI,k,l,imnpst

struct ChanModes {
    std::string type_a;  // list modes:   b (ban), e (ban exception), I (invite exception)
    std::string type_b;  // always-param: k (key)
    std::string type_c;  // set-only-param: l (limit)
    std::string type_d;  // no-param: i m n p s t

    /// Build the ISUPPORT CHANMODES string.
    std::string to_string() const {
        std::ostringstream oss;
        auto esc = [](const std::string& s) -> const std::string& { return s; };
        oss << esc(type_a) << ',' << esc(type_b) << ',' << esc(type_c) << ',' << esc(type_d);
        return oss.str();
    }

    /// Parse a CHANMODES string into categories.
    static ChanModes parse(const std::string& spec) {
        ChanModes modes;
        std::istringstream iss(spec);
        std::string seg;
        int idx = 0;
        while (std::getline(iss, seg, ',') && idx < 4) {
            switch (idx) {
                case 0: modes.type_a = seg; break;
                case 1: modes.type_b = seg; break;
                case 2: modes.type_c = seg; break;
                case 3: modes.type_d = seg; break;
            }
            ++idx;
        }
        return modes;
    }

    /// Default CHANMODES (RFC 2812).
    static ChanModes defaults() {
        return {"beI", "k", "l", "imnpst"};
    }

    /// Determine which category a given mode character belongs to.
    /// Returns 0=A, 1=B, 2=C, 3=D, or -1 if unknown.
    int category_of(char mode) const {
        if (type_a.find(mode) != std::string::npos) return 0;
        if (type_b.find(mode) != std::string::npos) return 1;
        if (type_c.find(mode) != std::string::npos) return 2;
        if (type_d.find(mode) != std::string::npos) return 3;
        return -1;
    }
};

// ============================================================================
// SECTION 13 : Message length enforcement (512 + tag extension)
// ============================================================================

/// @brief Maximum IRC message length (line) in bytes, per RFC 1459 § 2.3.
///        The 512 limit covers everything after the tags block, including the
///        trailing CR-LF.
constexpr size_t kMaxMessageLength    = 512;

/// @brief Maximum tag block size recommended by IRCv3.2 (8191 bytes before '@').
constexpr size_t kMaxTagBlockLength   = 8191;

/// @brief Maximum total line length (tags + message + CRLF).
constexpr size_t kMaxTotalLineLength  = kMaxTagBlockLength + 1 + kMaxMessageLength + 2;

/// @brief Enforce the 512-byte message limit (after tags).
///        Trims the trailing parameter (if any) to fit.
inline std::string enforce_message_limit(const std::string& message) {
    if (message.size() <= kMaxMessageLength) return message;

    // Split into parts up to the last colon (trailing parameter boundary).
    // If there's a trailing param, we truncate that; otherwise we truncate
    // the last word.
    size_t colon_pos = message.rfind(" :");
    if (colon_pos != std::string::npos) {
        // Keep prefix + " :" + as much of the trailer as fits
        size_t prefix_len = colon_pos + 2; // include " :"
        if (prefix_len >= kMaxMessageLength) {
            // Even the prefix is too long; take first 510 chars + CRLF room
            return message.substr(0, kMaxMessageLength - 2) + "\r\n";
        }
        size_t trailer_room = kMaxMessageLength - prefix_len;
        if (trailer_room > 0) {
            return message.substr(0, prefix_len + trailer_room);
        }
    }

    // No trailing parameter: just truncate
    return message.substr(0, kMaxMessageLength);
}

/// @brief Check if a message exceeds the tag block limit.
inline bool tags_too_long(const std::string& tag_block) {
    return tag_block.size() > kMaxTagBlockLength;
}

/// @brief Calculate the effective message length available after tags.
inline size_t available_message_length(const std::string& tag_block) {
    size_t tag_overhead = tag_block.empty() ? 0 : tag_block.size() + 1; // + '@'
    if (tag_overhead + kMaxMessageLength > kMaxTotalLineLength)
        return kMaxTotalLineLength - tag_overhead;
    return kMaxMessageLength;
}

// ============================================================================
// SECTION 14 : Line folding for long outgoing messages
// ============================================================================

/// @brief Fold a long message into multiple 512-byte-or-less chunks,
///        using the continuation rules described in IRC best practices.
///        Each chunk after the first gets the same prefix with the same
///        command but a truncated trailing parameter.
inline std::vector<std::string> line_fold(const std::string& prefix,
                                          const std::string& command,
                                          const std::string& middle,
                                          const std::string& trailing) {
    std::vector<std::string> result;
    if (trailing.empty()) {
        std::ostringstream oss;
        oss << ':' << prefix << ' ' << command;
        if (!middle.empty()) oss << ' ' << middle;
        std::string msg = oss.str();
        if (msg.size() <= kMaxMessageLength) {
            result.push_back(msg);
        } // else skip — no safe way to fold without trailing
        return result;
    }

    // First chunk: prefix command middle :chunk1
    // Subsequent:  prefix command middle :chunkN
    std::ostringstream hdr;
    hdr << ':' << prefix << ' ' << command;
    if (!middle.empty()) hdr << ' ' << middle;
    hdr << " :";
    std::string header = hdr.str();

    if (header.size() >= kMaxMessageLength) {
        // Header alone is too long; emit truncated header
        result.push_back(header.substr(0, kMaxMessageLength));
        return result;
    }

    size_t room = kMaxMessageLength - header.size();
    size_t pos  = 0;
    bool first   = true;

    while (pos < trailing.size()) {
        size_t chunk_size = std::min(room, trailing.size() - pos);
        std::ostringstream chunk;
        if (first) {
            chunk << header;
            first = false;
        } else {
            chunk << header;
        }
        chunk << trailing.substr(pos, chunk_size);
        pos += chunk_size;
        result.push_back(chunk.str());
    }

    return result;
}

// ============================================================================
// SECTION 15 : UTF-8 validation
// ============================================================================

/// @brief Validate a byte sequence as well-formed UTF-8.
///
/// Returns the number of valid code points scanned, or -1 on error.
/// Based on RFC 3629.
inline int validate_utf8(const std::string& s) {
    int cp_count = 0;
    size_t i = 0;

    while (i < s.size()) {
        unsigned char c = static_cast<unsigned char>(s[i]);
        size_t seq_len = 0;
        uint32_t code_point = 0;

        if ((c & 0x80u) == 0x00u) {
            // 0xxxxxxx — ASCII
            seq_len = 1;
            code_point = c;
        } else if ((c & 0xE0u) == 0xC0u) {
            // 110xxxxx 10xxxxxx
            seq_len = 2;
            code_point = c & 0x1Fu;
        } else if ((c & 0xF0u) == 0xE0u) {
            // 1110xxxx 10xxxxxx 10xxxxxx
            seq_len = 3;
            code_point = c & 0x0Fu;
        } else if ((c & 0xF8u) == 0xF0u) {
            // 11110xxx 10xxxxxx 10xxxxxx 10xxxxxx
            seq_len = 4;
            code_point = c & 0x07u;
        } else {
            return -1; // Invalid leading byte
        }

        if (i + seq_len > s.size()) return -1; // Truncated sequence

        // Overlong check
        if (seq_len == 2 && code_point < 0x80) return -1;
        if (seq_len == 3 && code_point < 0x800) return -1;
        if (seq_len == 4 && code_point < 0x10000) return -1;

        // Surrogate check
        if (seq_len == 3 && code_point >= 0xD800 && code_point <= 0xDFFF) return -1;

        // Max code point check
        if (seq_len == 4 && code_point > 0x10FFFF) return -1;

        // Read continuation bytes
        for (size_t j = 1; j < seq_len; ++j) {
            unsigned char cb = static_cast<unsigned char>(s[i + j]);
            if ((cb & 0xC0u) != 0x80u) return -1; // Not a continuation byte
            code_point = (code_point << 6) | (cb & 0x3Fu);
        }

        i += seq_len;
        ++cp_count;
    }

    return cp_count;
}

/// @brief Sanitize a string by replacing or stripping invalid UTF-8 sequences.
inline std::string sanitize_utf8(const std::string& input, char replacement = '?') {
    std::string out;
    out.reserve(input.size());
    size_t i = 0;

    while (i < input.size()) {
        unsigned char c = static_cast<unsigned char>(input[i]);
        size_t seq_len = 0;

        if ((c & 0x80u) == 0x00u) {
            seq_len = 1;
        } else if ((c & 0xE0u) == 0xC0u) {
            seq_len = 2;
        } else if ((c & 0xF0u) == 0xE0u) {
            seq_len = 3;
        } else if ((c & 0xF8u) == 0xF0u) {
            seq_len = 4;
        } else {
            out.push_back(replacement);
            ++i;
            continue;
        }

        if (i + seq_len > input.size()) {
            for (size_t j = i; j < input.size(); ++j)
                out.push_back(replacement);
            break;
        }

        bool valid = true;
        for (size_t j = 1; j < seq_len; ++j) {
            unsigned char cb = static_cast<unsigned char>(input[i + j]);
            if ((cb & 0xC0u) != 0x80u) {
                valid = false;
                break;
            }
        }

        if (valid) {
            for (size_t j = 0; j < seq_len; ++j) out.push_back(input[i + j]);
        } else {
            out.push_back(replacement);
        }
        i += seq_len;
    }

    return out;
}

/// @brief Count Unicode code points in a valid UTF-8 string.
inline size_t utf8_codepoint_count(const std::string& s) {
    size_t count = 0;
    for (size_t i = 0; i < s.size(); ++i) {
        unsigned char c = static_cast<unsigned char>(s[i]);
        if ((c & 0xC0u) != 0x80u) ++count; // Not a continuation byte
    }
    return count;
}

/// @brief Truncate a UTF-8 string to at most N code points.
inline std::string utf8_truncate_codepoints(const std::string& s, size_t max_cp) {
    size_t count = 0;
    size_t i = 0;
    for (; i < s.size() && count < max_cp; ++i) {
        unsigned char c = static_cast<unsigned char>(s[i]);
        if ((c & 0xC0u) != 0x80u) ++count;
    }
    return s.substr(0, i);
}

// ============================================================================
// SECTION 16 : Server link protocol — SERVER, PROTOCTL, netburst
// ============================================================================

/// @brief Server link state machine.
enum class ServerLinkState : uint8_t {
    kDisconnected  = 0,
    kConnecting    = 1,
    kWaitPass      = 2,
    kWaitServer    = 3,
    kWaitBurst     = 4,
    kBursting      = 5,
    kLinked        = 6,
};

/// @brief PROTOCTL token: feature flags negotiated during server linking.
enum class ProtoCtlFlag : uint32_t {
    kNoQ          = 0,   // NOQUIT — suppress QUIT on netsplit
    kSJ3          = 1,   // services join version 3
    kTkLext       = 2,   // extended TKLINE
    kNickv2       = 3,   // NICKv2
    kVl           = 4,   // VL (vhost linking)
    kSid          = 5,   // SID (server IDs)
    kEsvid        = 6,   // ESVID (extended SVID)
    kMtk          = 7,   // MTAGS
    kFmc          = 8,   // FNC (forced nick change)
    kEa           = 9,   // EAUTH
    kEliVl        = 10,  // ELIVEL
};

constexpr const char* kProtoCtlNames[] = {
    "NOQUIT", "SJ3", "TKLEXT", "NICKv2",
    "VL", "SID", "ESVID", "MTAGS",
    "FNC", "EAUTH", "ELIVEL"
};

/// @brief PROTOCTL token set.
class ProtoCtl {
public:
    void set(ProtoCtlFlag f) { flags_.set(static_cast<size_t>(f)); }
    bool has(ProtoCtlFlag f) const { return flags_.test(static_cast<size_t>(f)); }
    void parse(const std::string& token) {
        if (token == "NOQUIT")  set(ProtoCtlFlag::kNoQ);
        else if (token == "SJ3")     set(ProtoCtlFlag::kSJ3);
        else if (token == "TKLEXT")  set(ProtoCtlFlag::kTkLext);
        else if (token == "NICKv2")  set(ProtoCtlFlag::kNickv2);
        else if (token == "VL")      set(ProtoCtlFlag::kVl);
        else if (token == "SID")     set(ProtoCtlFlag::kSid);
        else if (token == "ESVID")   set(ProtoCtlFlag::kEsvid);
        else if (token == "MTAGS")   set(ProtoCtlFlag::kMtk);
        else if (token == "FNC")     set(ProtoCtlFlag::kFmc);
        else if (token == "EAUTH")   set(ProtoCtlFlag::kEa);
        else if (token == "ELIVEL") set(ProtoCtlFlag::kEliVl);
    }
    std::string serialize() const {
        std::ostringstream oss;
        for (size_t i = 0; i < sizeof(kProtoCtlNames)/sizeof(kProtoCtlNames[0]); ++i) {
            if (flags_.test(i)) {
                if (oss.tellp() > 0) oss << ' ';
                oss << kProtoCtlNames[i];
            }
        }
        return oss.str();
    }
private:
    std::bitset<32> flags_;
};

/// @brief Server introduction message:  SERVER servername hopcount :serverinfo
inline std::string server_intro(const std::string& server_name, int hopcount,
                                const std::string& info) {
    std::ostringstream oss;
    oss << "SERVER " << server_name << ' ' << hopcount << " :" << info;
    return oss.str();
}

/// @brief PROTOCTL command:  PROTOCTL TOKEN1 TOKEN2 ...
inline std::string protoctl_command(const ProtoCtl& proto) {
    std::ostringstream oss;
    oss << "PROTOCTL " << proto.serialize();
    return oss.str();
}

/// @brief Server burst container — holds all state sent during netburst.
struct ServerBurst {
    std::string server_name;
    std::string server_sid;     // SID — 3-character server ID
    int         hopcount = 0;

    // All users on this server: nick, hopcount, ts, umodes, ident, host, ip, uid, realname
    struct BurstUser {
        std::string nick;
        int         hopcount  = 0;
        time_t      ts        = 0;
        std::string user_modes;
        std::string ident;
        std::string host;
        std::string ip;
        std::string uid;          // UID — 9-character user ID
        std::string realname;
        std::string account;      // services account name
        std::string cloaked_host; // vhost
        bool        oper  = false;
        bool        away  = false;
        std::string away_msg;
    };

    /// Build a NICK/UID burst line for a user.
    /// Format (with SID/UID):  :sid UID nick hopcount ts umodes ident host ip uid :realname
    /// Format (without SID/UID): NICK nick hopcount ts umodes ident host :realname
    static std::string user_burst_line(const std::string& sid, const BurstUser& u,
                                       bool use_sid_uid) {
        std::ostringstream oss;
        if (use_sid_uid) {
            oss << ':' << sid << " UID " << u.nick << ' ' << u.hopcount << ' '
                << u.ts << ' ' << u.user_modes << ' '
                << u.ident << ' ' << u.host << ' ' << u.ip << ' ' << u.uid
                << " :" << u.realname;
        } else {
            oss << "NICK " << u.nick << ' ' << u.hopcount << ' '
                << u.ts << ' ' << u.user_modes << ' '
                << u.ident << ' ' << u.host << " :" << u.realname;
        }
        return oss.str();
    }

    /// Build an SJOIN (channel burst) line.
    /// Format:  :sid SJOIN ts channel +modes :@nick1 +nick2 ...
    static std::string sjoin_line(const std::string& sid, time_t chan_ts,
                                  const std::string& channel, const std::string& modes,
                                  const std::vector<std::string>& members) {
        std::ostringstream oss;
        oss << ':' << sid << " SJOIN " << chan_ts << ' ' << channel << ' '
            << modes << " :";
        for (size_t i = 0; i < members.size(); ++i) {
            if (i > 0) oss << ' ';
            oss << members[i];
        }
        return oss.str();
    }

    /// Build an SID introduction.
    /// Format:  :peer_sid SID servername hopcount sid :serverinfo
    static std::string sid_intro(const std::string& peer_sid,
                                 const std::string& server_name, int hopcount,
                                 const std::string& sid, const std::string& info) {
        std::ostringstream oss;
        oss << ':' << peer_sid << " SID " << server_name << ' '
            << hopcount << ' ' << sid << " :" << info;
        return oss.str();
    }

    /// End-of-burst:  :sid EOB
    static std::string eob(const std::string& sid) {
        std::ostringstream oss;
        oss << ':' << sid << " EOB";
        return oss.str();
    }
};

// ============================================================================
// SECTION 17 : TS6 protocol basics (elemental/eighties-style linking)
// ============================================================================

/// @brief TS6 numeric nick prefix (UID-based).
///
/// In TS6, users are identified by a 9-character UID:
///   Digit + 5 alphanum + 2-letter SID suffix
///   e.g.: 001AAAAAA  →  UID
///
/// SID is a 3-character server ID:  Digit + 2 alphanum
///   e.g.: 1AA

/// Validate a TS6 SID (3 chars, digit + 2 alphanum).
inline bool valid_sid(const std::string& sid) {
    if (sid.size() != 3) return false;
    if (!isdigit(sid[0])) return false;
    return isalnum(sid[1]) && isalnum(sid[2]);
}

/// Validate a TS6 UID (9 chars, digit + 5 alphanum + 2-letter suffix).
inline bool valid_uid(const std::string& uid) {
    if (uid.size() != 9) return false;
    if (!isdigit(uid[0])) return false;
    for (int i = 1; i < 6; ++i)
        if (!isalnum(uid[i])) return false;
    for (int i = 6; i < 9; ++i)
        if (!isalpha(uid[i])) return false;
    return true;
}

/// Parse the SID from a UID (last 3 characters).
inline std::string sid_from_uid(const std::string& uid) {
    if (uid.size() >= 3) return uid.substr(uid.size() - 3);
    return {};
}

/// @brief TS6 protocol commands.
namespace ts6 {

/// ENCAP — encapsulated server-to-server command.
/// Format:  :sid ENCAP destination command params...
inline std::string encap(const std::string& source_sid, const std::string& destination,
                         const std::string& command, const std::string& params) {
    std::ostringstream oss;
    oss << ':' << source_sid << " ENCAP " << destination << ' '
        << command;
    if (!params.empty()) oss << ' ' << params;
    return oss.str();
}

/// TS6 NICK introduction.
/// :sid UID nick hopcount ts umodes ident vhost ip uid :realname
inline std::string uid_intro(const std::string& sid, const std::string& nick,
                             int hopcount, time_t ts, const std::string& umodes,
                             const std::string& ident, const std::string& vhost,
                             const std::string& ip, const std::string& uid,
                             const std::string& realname) {
    std::ostringstream oss;
    oss << ':' << sid << " UID " << nick << ' ' << hopcount << ' '
        << ts << ' ' << umodes << ' ' << ident << ' ' << vhost
        << ' ' << ip << ' ' << uid << " :" << realname;
    return oss.str();
}

/// TS6 SID server introduction.
/// :peer_sid SID servername hopcount sid :description
inline std::string sid_intro(const std::string& peer_sid, const std::string& server_name,
                             int hopcount, const std::string& sid,
                             const std::string& description) {
    std::ostringstream oss;
    oss << ':' << peer_sid << " SID " << server_name << ' '
        << hopcount << ' ' << sid << " :" << description;
    return oss.str();
}

/// TS6 SQUIT — server quit.
/// :sid SQUIT target_server :reason
inline std::string squit(const std::string& sid, const std::string& target,
                         const std::string& reason) {
    std::ostringstream oss;
    oss << ':' << sid << " SQUIT " << target << " :" << reason;
    return oss.str();
}

/// TS6 KILL — user kill.
/// :sid KILL uid :reason
inline std::string kill(const std::string& sid, const std::string& uid,
                        const std::string& reason) {
    std::ostringstream oss;
    oss << ':' << sid << " KILL " << uid << " :" << reason;
    return oss.str();
}

/// TS6 SJOIN — channel burst.
/// :sid SJOIN ts channel +modes :@uid1 +uid2 ...
inline std::string sjoin(const std::string& sid, time_t chan_ts,
                         const std::string& channel, const std::string& modes,
                         const std::vector<std::string>& uid_members) {
    std::ostringstream oss;
    oss << ':' << sid << " SJOIN " << chan_ts << ' ' << channel << ' '
        << modes << " :";
    for (size_t i = 0; i < uid_members.size(); ++i) {
        if (i > 0) oss << ' ';
        oss << uid_members[i];
    }
    return oss.str();
}

/// TS6 BMASK — ban/except/invex masks.
/// :sid BMASK ts channel type :masks
inline std::string bmask(const std::string& sid, time_t ts,
                         const std::string& channel, char type,
                         const std::vector<std::string>& masks) {
    std::ostringstream oss;
    oss << ':' << sid << " BMASK " << ts << ' ' << channel << ' ' << type << " :";
    for (size_t i = 0; i < masks.size(); ++i) {
        if (i > 0) oss << ' ';
        oss << masks[i];
    }
    return oss.str();
}

/// TS6 TMODE — topic mode.
/// :sid TMODE ts channel topic_setter_uid topic_ts :topic
inline std::string tmode(const std::string& sid, time_t ts,
                         const std::string& channel,
                         const std::string& setter_uid, time_t topic_ts,
                         const std::string& topic) {
    std::ostringstream oss;
    oss << ':' << sid << " TMODE " << ts << ' ' << channel << ' '
        << '+' << setter_uid << ' ' << topic_ts << " :" << topic;
    return oss.str();
}

/// TS6 EOB — end of burst.
inline std::string eob(const std::string& sid) {
    return ":" + sid + " EOB";
}

/// TS6 PING / PONG for server links.
inline std::string server_ping(const std::string& source_sid,
                               const std::string& target_sid) {
    std::ostringstream oss;
    oss << ':' << source_sid << " PING " << target_sid << " :" << source_sid;
    return oss.str();
}

inline std::string server_pong(const std::string& source_sid,
                               const std::string& target_sid) {
    std::ostringstream oss;
    oss << ':' << source_sid << " PONG " << target_sid << " :" << source_sid;
    return oss.str();
}

} // namespace ts6

// ============================================================================
// SECTION 18 : Message parser — combined IRC + IRCv3 line parser
// ============================================================================

/// @brief A fully-parsed IRC message (including tags).
struct ParsedMessage {
    MessageTags              tags;
    std::string              prefix;       // servername or nick!user@host
    std::string              command;
    std::vector<std::string> params;       // middle params
    std::string              trailing;     // final parameter (after colon)
    bool                     has_trailing = false;

    /// Serialize back to a raw IRC wire line (without tags).
    std::string to_line() const {
        std::ostringstream oss;
        if (!prefix.empty()) oss << ':' << prefix << ' ';
        oss << command;
        for (auto& p : params) oss << ' ' << p;
        if (has_trailing) oss << " :" << trailing;
        return oss.str();
    }

    /// Serialize with tags (full wire line).
    std::string to_full_line() const {
        std::ostringstream oss;
        std::string tb = tags.serialize();
        if (!tb.empty()) oss << '@' << tb << ' ';
        if (!prefix.empty()) oss << ':' << prefix << ' ';
        oss << command;
        for (auto& p : params) oss << ' ' << p;
        if (has_trailing) oss << " :" << trailing;
        return oss.str();
    }

    /// Parse a single raw IRC line (without the terminating CR-LF).
    static ParsedMessage parse(const std::string& raw_line) {
        ParsedMessage msg;
        size_t pos = 0;
        size_t len = raw_line.size();

        // --- Tags ---
        if (pos < len && raw_line[pos] == '@') {
            size_t tag_end = raw_line.find(' ', pos);
            std::string tag_block;
            if (tag_end == std::string::npos) {
                tag_block = raw_line.substr(pos + 1);
                pos = len;
            } else {
                tag_block = raw_line.substr(pos + 1, tag_end - pos - 1);
                pos = tag_end + 1;
            }
            msg.tags.parse(tag_block);
        }

        // Skip whitespace
        while (pos < len && raw_line[pos] == ' ') ++pos;

        // --- Prefix ---
        if (pos < len && raw_line[pos] == ':') {
            size_t prefix_end = raw_line.find(' ', pos);
            if (prefix_end == std::string::npos) {
                msg.prefix = raw_line.substr(pos + 1);
                return msg; // only prefix, no command
            }
            msg.prefix = raw_line.substr(pos + 1, prefix_end - pos - 1);
            pos = prefix_end + 1;
        }

        // Skip whitespace
        while (pos < len && raw_line[pos] == ' ') ++pos;

        // --- Command ---
        size_t cmd_end = raw_line.find(' ', pos);
        if (cmd_end == std::string::npos) {
            msg.command = raw_line.substr(pos);
            // Uppercase the command
            for (auto& c : msg.command) c = static_cast<char>(toupper(c));
            return msg;
        }
        msg.command = raw_line.substr(pos, cmd_end - pos);
        for (auto& c : msg.command) c = static_cast<char>(toupper(c));
        pos = cmd_end + 1;

        // --- Params and trailing ---
        while (pos < len) {
            while (pos < len && raw_line[pos] == ' ') ++pos;
            if (pos >= len) break;

            if (raw_line[pos] == ':') {
                // Everything remaining is the trailing parameter
                msg.trailing     = raw_line.substr(pos + 1);
                msg.has_trailing = true;
                break;
            }

            size_t param_end = raw_line.find(' ', pos);
            if (param_end == std::string::npos) {
                msg.params.push_back(raw_line.substr(pos));
                break;
            }
            msg.params.push_back(raw_line.substr(pos, param_end - pos));
            pos = param_end + 1;
        }

        return msg;
    }
};

// ============================================================================
// SECTION 19 : ISUPPORT (RPL_BOUNCE / 005) token builder
// ============================================================================

/// @brief ISUPPORT token registry.
class ISupportBuilder {
public:
    ISupportBuilder() { set_defaults(); }

    void set_defaults() {
        tokens_["CHANNELLEN"]    = "64";
        tokens_["NICKLEN"]       = "30";
        tokens_["TOPICLEN"]      = "390";
        tokens_["AWAYLEN"]       = "390";
        tokens_["KICKLEN"]       = "390";
        tokens_["MAXLIST"]       = "beI:50";
        tokens_["CHANMODES"]     = ChanModes::defaults().to_string();
        tokens_["PREFIX"]        = "(qaohv)~&@%+";
        tokens_["STATUSMSG"]     = "~&@%+";
        tokens_["CASEMAPPING"]   = "rfc1459";
        tokens_["NETWORK"]       = "ProgressiveNet";
        tokens_["CHANTYPES"]     = "#&";
        tokens_["MODES"]         = "20";
        tokens_["SILENCE"]       = "50";
        tokens_["MONITOR"]       = "100";
        tokens_["WATCH"]         = "128";
    }

    void set(const std::string& key, const std::string& value) {
        tokens_[key] = value;
    }

    void set_case_mapping(CaseMapping cm) {
        tokens_["CASEMAPPING"] = CaseMapRegistry::to_isupport(cm);
    }

    /// Build the full RPL_BOUNCE line:  :server 005 nick TOKEN1=VAL1 TOKEN2 ... :are supported...
    std::string build(const std::string& server, const std::string& nick) const {
        std::ostringstream oss;
        oss << ':' << server << " 005 " << nick;
        for (auto& kv : tokens_) {
            oss << ' ' << kv.first;
            if (!kv.second.empty()) oss << '=' << kv.second;
        }
        oss << " :are supported by this server";
        return oss.str();
    }

    /// Split the output into multiple lines if it exceeds 13 tokens per line.
    std::vector<std::string> build_multiline(const std::string& server,
                                             const std::string& nick) const {
        std::vector<std::string> lines;
        std::ostringstream oss;
        int count = 0;

        oss << ':' << server << " 005 " << nick;
        for (auto& kv : tokens_) {
            if (count > 0 && count % 13 == 0) {
                oss << " :are supported by this server";
                lines.push_back(oss.str());
                oss.str("");
                oss << ':' << server << " 005 " << nick;
            }
            oss << ' ' << kv.first;
            if (!kv.second.empty()) oss << '=' << kv.second;
            ++count;
        }
        oss << " :are supported by this server";
        lines.push_back(oss.str());
        return lines;
    }

private:
    std::unordered_map<std::string, std::string> tokens_;
};

// ============================================================================
// SECTION 20 : Numeric reply builder — convenience wrappers
// ============================================================================

/// @brief Build a raw numeric reply string.
///        :server NNN nick [params] :message
///        or for errors / multi-line:  :server NNN nick params :message
class NumericBuilder {
public:
    /// Build a simple numeric reply with format-string-like substitution.
    /// The `format` argument is a printf-style format (uses snprintf internally).
    static std::string build(uint16_t numeric, const std::string& server,
                             const std::string& target,
                             const char* format, ...) {
        char buf[512];
        va_list args;
        va_start(args, format);
        int n = vsnprintf(buf, sizeof(buf), format, args);
        va_end(args);

        std::string body = (n > 0) ? std::string(buf, std::min(static_cast<size_t>(n),
                                                               sizeof(buf) - 1))
                                   : std::string();

        char num_str[4];
        snprintf(num_str, sizeof(num_str), "%03u", numeric);

        std::ostringstream oss;
        oss << ':' << server << ' ' << num_str << ' ' << target << ' ' << body;
        return oss.str();
    }

    /// Convenience: no format, just a raw suffix.
    static std::string raw(uint16_t numeric, const std::string& server,
                           const std::string& target, const std::string& suffix) {
        char num_str[4];
        snprintf(num_str, sizeof(num_str), "%03u", numeric);
        std::ostringstream oss;
        oss << ':' << server << ' ' << num_str << ' ' << target << ' ' << suffix;
        return oss.str();
    }

    /// Build a reply from the default format string in the table, substituting
    /// the provided arguments.
    static std::string from_table(uint16_t numeric, const std::string& server,
                                  const std::string& target,
                                  const std::vector<std::string>& fmt_args) {
        const char* fmt = numeric_format(numeric);
        if (!fmt) {
            // Fallback: just emit the numeric with the args space-joined
            std::ostringstream oss;
            char num_str[4];
            snprintf(num_str, sizeof(num_str), "%03u", numeric);
            oss << ':' << server << ' ' << num_str << ' ' << target;
            for (auto& a : fmt_args) oss << ' ' << a;
            return oss.str();
        }

        // Simple substitution: replace %s/%d/%lu/%llu/%c placeholders
        std::string result;
        size_t arg_idx = 0;
        const char* p = fmt;

        // Skip leading ':' if present in format
        bool has_colon = (*p == ':');
        if (has_colon) ++p;

        result.reserve(strlen(p) + 128);

        while (*p) {
            if (*p == '%' && *(p+1) && arg_idx < fmt_args.size()) {
                char spec = *(p+1);
                if (spec == 's' || spec == 'd' || spec == 'u' ||
                    spec == 'c' || spec == 'l') {
                    // Handle %lu %llu %ld
                    if (spec == 'l') {
                        if (*(p+2) == 'l' && *(p+3) == 'u') {
                            result += fmt_args[arg_idx];
                            p += 4;
                        } else if (*(p+2) == 'u') {
                            result += fmt_args[arg_idx];
                            p += 3;
                        } else if (*(p+2) == 'd') {
                            result += fmt_args[arg_idx];
                            p += 3;
                        } else {
                            result += fmt_args[arg_idx];
                            p += 2;
                        }
                    } else {
                        result += fmt_args[arg_idx];
                        p += 2;
                    }
                    ++arg_idx;
                    continue;
                }
            }
            result += *p;
            ++p;
        }

        char num_str[4];
        snprintf(num_str, sizeof(num_str), "%03u", numeric);
        std::ostringstream oss;
        oss << ':' << server << ' ' << num_str << ' ' << target << ' ';
        if (has_colon) oss << ':';
        oss << result;
        return oss.str();
    }
};

// ============================================================================
// SECTION 21 : SASL (Simple Authentication and Security Layer) helpers
// ============================================================================

/// @brief SASL authentication state machine.
enum class SASLState : uint8_t {
    kNone        = 0,
    kWaitAuth    = 1,   // Client sent AUTHENTICATE, waiting for mechanism
    kInProgress  = 2,   // Authentication exchange active
    kSuccess     = 3,
    kFailed      = 4,
    kAborted     = 5,
};

/// @brief SASL session tracker.
class SASLSession {
public:
    void start(const std::string& mechanism) {
        mechanism_  = mechanism;
        state_      = SASLState::kInProgress;
        buffer_.clear();
    }

    void abort() {
        state_ = SASLState::kAborted;
        buffer_.clear();
    }

    void fail() {
        state_ = SASLState::kFailed;
        buffer_.clear();
    }

    void succeed() {
        state_ = SASLState::kSuccess;
    }

    void reset() {
        state_ = SASLState::kNone;
        mechanism_.clear();
        buffer_.clear();
    }

    void append_data(const std::string& data) { buffer_ += data; }
    const std::string& buffer() const { return buffer_; }
    void clear_buffer() { buffer_.clear(); }

    SASLState state() const { return state_; }
    const std::string& mechanism() const { return mechanism_; }
    bool is_active() const { return state_ == SASLState::kInProgress; }

    /// Build an AUTHENTICATE response line.
    static std::string authenticate_response(const std::string& data) {
        // IRC AUTHENTICATE:  "AUTHENTICATE " + base64-or-'+'
        if (data.empty()) return "AUTHENTICATE +";
        return "AUTHENTICATE " + data;
    }

    /// Decode the AUTHENTICATE command parameter.
    /// "*" = abort.  "+" or empty = zero-length block.
    static bool decode_authenticate_param(const std::string& param,
                                          bool* is_abort, std::string* out_data) {
        if (param == "*") {
            *is_abort = true;
            return true;
        }
        *is_abort = false;
        if (param == "+") {
            *out_data = "";
            return true;
        }
        *out_data = param;
        return true;
    }

private:
    SASLState state_ = SASLState::kNone;
    std::string mechanism_;
    std::string buffer_;
};

// ============================================================================
// SECTION 22 : Secure connection & STARTTLS / STS helpers
// ============================================================================

/// @brief STS (Strict Transport Security) policy.
struct STSPolicy {
    std::string host;
    uint16_t    port           = 6697;
    int64_t     duration_secs  = 0;   // max-age, 0 = not set
    bool        enabled        = false;
    bool        preload        = false;

    /// Build the STS capability value:  sts=port,duration,preload
    std::string to_cap_value() const {
        std::ostringstream oss;
        oss << "sts=" << port;
        if (duration_secs > 0) {
            oss << ',' << duration_secs;
            if (preload) oss << ",preload";
        }
        return oss.str();
    }

    /// Parse from raw STS cap value.
    static STSPolicy parse(const std::string& cap_value) {
        STSPolicy policy;
        std::istringstream iss(cap_value);
        std::string token;
        if (std::getline(iss, token, ',')) {
            policy.port = static_cast<uint16_t>(strtoul(token.c_str(), nullptr, 10));
        }
        if (std::getline(iss, token, ',')) {
            policy.duration_secs = strtoll(token.c_str(), nullptr, 10);
            policy.enabled = (policy.duration_secs > 0);
        }
        if (std::getline(iss, token, ',')) {
            policy.preload = (token == "preload");
        }
        return policy;
    }
};

// ============================================================================
// SECTION 23 : INVITE-NOTIFY handler
// ============================================================================

/// @brief Build an INVITE notification for invite-notify capability.
///        :inviter!user@host INVITE target_nick :#channel
inline std::string invite_notify(const std::string& inviter_nick,
                                 const std::string& inviter_user,
                                 const std::string& inviter_host,
                                 const std::string& target_nick,
                                 const std::string& channel) {
    std::ostringstream oss;
    oss << ':' << inviter_nick << '!' << inviter_user << '@' << inviter_host
        << " INVITE " << target_nick << " :" << channel;
    return oss.str();
}

// ============================================================================
// SECTION 24 : Cap-notify handling
// ============================================================================

/// @brief Build CAP NEW/DEL messages for cap-notify.
///        :server CAP nick NEW :cap1 cap2 ...
///        :server CAP nick DEL :cap1 cap2 ...
inline std::string cap_new(const std::string& server, const std::string& nick,
                           const std::vector<std::string>& caps) {
    std::ostringstream oss;
    oss << ':' << server << " CAP " << nick << " NEW :";
    for (size_t i = 0; i < caps.size(); ++i) {
        if (i > 0) oss << ' ';
        oss << caps[i];
    }
    return oss.str();
}

inline std::string cap_del(const std::string& server, const std::string& nick,
                           const std::vector<std::string>& caps) {
    std::ostringstream oss;
    oss << ':' << server << " CAP " << nick << " DEL :";
    for (size_t i = 0; i < caps.size(); ++i) {
        if (i > 0) oss << ' ';
        oss << caps[i];
    }
    return oss.str();
}

/// @brief Build CAP ACK/NAK messages.
inline std::string cap_ack(const std::string& server, const std::string& nick,
                           const std::vector<std::string>& caps) {
    std::ostringstream oss;
    oss << ':' << server << " CAP " << nick << " ACK :";
    for (size_t i = 0; i < caps.size(); ++i) {
        if (i > 0) oss << ' ';
        oss << caps[i];
    }
    return oss.str();
}

inline std::string cap_nak(const std::string& server, const std::string& nick,
                           const std::vector<std::string>& caps) {
    std::ostringstream oss;
    oss << ':' << server << " CAP " << nick << " NAK :";
    for (size_t i = 0; i < caps.size(); ++i) {
        if (i > 0) oss << ' ';
        oss << caps[i];
    }
    return oss.str();
}

/// @brief Build CAP LIST response with values.
///        :server CAP nick LIST :cap [= value] [cap2=value2] ...
inline std::string cap_list(const std::string& server, const std::string& nick,
                            const std::vector<std::pair<std::string, std::string>>& caps_with_values,
                            const std::vector<std::string>& caps_no_value) {
    std::ostringstream oss;
    oss << ':' << server << " CAP " << nick << " LIST :";
    bool first = true;
    for (auto& cv : caps_with_values) {
        if (!first) oss << ' ';
        oss << cv.first;
        if (!cv.second.empty()) oss << '=' << cv.second;
        first = false;
    }
    for (auto& cn : caps_no_value) {
        if (!first) oss << ' ';
        oss << cn;
        first = false;
    }
    return oss.str();
}

// ============================================================================
// SECTION 25 : Message rate limiting / flood protection helpers
// ============================================================================

/// @brief Simple token-bucket rate limiter.
class TokenBucket {
public:
    TokenBucket(double rate_per_sec, double burst_size)
        : rate_(rate_per_sec), burst_(burst_size), tokens_(burst_size) {
        last_update_ = std::chrono::steady_clock::now();
    }

    /// Attempt to consume one token.  Returns true if allowed.
    bool consume() {
        refill();
        if (tokens_ >= 1.0) {
            tokens_ -= 1.0;
            return true;
        }
        return false;
    }

    /// Attempt to consume N tokens.
    bool consume_n(double n) {
        refill();
        if (tokens_ >= n) {
            tokens_ -= n;
            return true;
        }
        return false;
    }

    /// Refill tokens based on elapsed time.
    void refill() {
        auto now = std::chrono::steady_clock::now();
        double elapsed = std::chrono::duration<double>(now - last_update_).count();
        tokens_ = std::min(burst_, tokens_ + elapsed * rate_);
        last_update_ = now;
    }

    /// Reset to full burst.
    void reset() {
        tokens_ = burst_;
        last_update_ = std::chrono::steady_clock::now();
    }

    /// Adjust rate.
    void set_rate(double rate_per_sec) { rate_ = rate_per_sec; }

private:
    double rate_;
    double burst_;
    double tokens_;
    std::chrono::steady_clock::time_point last_update_;
};

// ============================================================================
// SECTION 26 : Hostname / nick validation helpers
// ============================================================================

/// @brief Validate an IRC nickname (RFC 2812 § 2.3.1).
///
/// Nicknames must begin with a letter or special character, and may contain
/// letters, digits, and the special characters: - _ [ ] { } \ ` | ^
inline bool valid_nickname(const std::string& nick, size_t max_len = 30) {
    if (nick.empty() || nick.size() > max_len) return false;
    char first = nick[0];
    if (!isalpha(first) && first != '[' && first != ']' &&
        first != '\\' && first != '`' && first != '_' &&
        first != '^' && first != '{' && first != '|' &&
        first != '}') {
        return false;
    }
    for (size_t i = 1; i < nick.size(); ++i) {
        char c = nick[i];
        if (!isalnum(c) && c != '-' && c != '_' &&
            c != '[' && c != ']' && c != '{' && c != '}' &&
            c != '\\' && c != '`' && c != '|' && c != '^') {
            return false;
        }
    }
    return true;
}

/// @brief Validate a channel name (RFC 2811).
///        Must begin with # or &, length 1-64.
inline bool valid_channel_name(const std::string& chan, size_t max_len = 64) {
    if (chan.empty() || chan.size() > max_len) return false;
    if (chan[0] != '#' && chan[0] != '&') return false;
    if (chan.size() < 2) return false;
    // Channel names cannot contain spaces, commas, or control chars
    for (char c : chan) {
        if (c == ' ' || c == ',' || c == ':' || c == 7 || (c >= 0 && c < 32))
            return false;
    }
    return true;
}

/// @brief Validate an IRC hostname (simple check).
inline bool valid_hostname(const std::string& host) {
    if (host.empty() || host.size() > 63) return false;
    for (char c : host) {
        if (!isalnum(c) && c != '.' && c != '-' && c != ':') return false;
    }
    return true;
}

// ============================================================================
// SECTION 27 : Miscellaneous protocol utilities
// ============================================================================

/// @brief Strip the CR/LF from a raw IRC line.
inline std::string strip_crlf(const std::string& line) {
    std::string s = line;
    while (!s.empty() && (s.back() == '\r' || s.back() == '\n'))
        s.pop_back();
    return s;
}

/// @brief Append CR-LF to a line for wire transmission.
inline std::string append_crlf(const std::string& line) {
    return line + "\r\n";
}

/// @brief Parse a nick!user@host mask into components.
struct UserMask {
    std::string nick;
    std::string user;
    std::string host;

    static UserMask parse(const std::string& mask) {
        UserMask um;
        size_t excl = mask.find('!');
        size_t at   = mask.find('@');

        if (excl != std::string::npos) {
            um.nick = mask.substr(0, excl);
            if (at != std::string::npos && at > excl) {
                um.user = mask.substr(excl + 1, at - excl - 1);
                um.host = mask.substr(at + 1);
            } else {
                um.user = mask.substr(excl + 1);
            }
        } else if (at != std::string::npos) {
            um.nick = mask.substr(0, at);
            um.host = mask.substr(at + 1);
        } else {
            um.nick = mask;
        }
        return um;
    }

    std::string to_string() const {
        std::ostringstream oss;
        oss << nick;
        if (!user.empty()) oss << '!' << user;
        if (!host.empty()) oss << '@' << host;
        return oss.str();
    }
};

/// @brief Mask matching — basic wildcard support (* and ?).
inline bool mask_match(const std::string& pattern, const std::string& target,
                       const CaseMapTable* cmap = nullptr) {
    std::string pat = cmap ? cmap->folded(pattern) : pattern;
    std::string tgt = cmap ? cmap->folded(target) : target;

    size_t pi = 0, ti = 0;
    size_t star_pi = std::string::npos;
    size_t match_ti = 0;

    while (ti < tgt.size()) {
        if (pi < pat.size() && (pat[pi] == '?' || pat[pi] == tgt[ti])) {
            ++pi; ++ti;
        } else if (pi < pat.size() && pat[pi] == '*') {
            star_pi  = pi++;
            match_ti = ti;
        } else if (star_pi != std::string::npos) {
            pi = star_pi + 1;
            ti = ++match_ti;
        } else {
            return false;
        }
    }

    while (pi < pat.size() && pat[pi] == '*') ++pi;
    return pi == pat.size();
}

/// @brief Format the current time for RPL_CREATED.
inline std::string created_time_string() {
    time_t now = time(nullptr);
    struct tm tm_buf;
    gmtime_r(&now, &tm_buf);
    char buf[64];
    strftime(buf, sizeof(buf), "%a %b %d %Y at %H:%M:%S %Z", &tm_buf);
    return buf;
}

/// @brief Format idle time for WHOIS.
inline std::string format_idle_time(time_t signon, time_t now) {
    time_t idle = now - signon;
    if (idle < 0) idle = 0;

    long days  = idle / 86400;
    long hours = (idle % 86400) / 3600;
    long mins  = (idle % 3600) / 60;
    long secs  = idle % 60;

    std::ostringstream oss;
    if (days > 0) oss << days << "d ";
    if (hours > 0 || days > 0) oss << hours << "h ";
    oss << mins << "m " << secs << "s";
    return oss.str();
}

// ============================================================================
// SECTION 28 : Multi-line MOTD / HELP builders
// ============================================================================

/// @brief Helper to emit multi-line numeric replies (MOTD, HELP, INFO).
class MultiLineBuilder {
public:
    MultiLineBuilder(uint16_t line_numeric, uint16_t start_numeric,
                     uint16_t end_numeric,
                     const std::string& server, const std::string& target)
        : line_num_(line_numeric)
        , start_num_(start_numeric)
        , end_num_(end_numeric)
        , server_(server)
        , target_(target) {}

    /// Add a content line.
    void add_line(const std::string& text) {
        lines_.push_back(text);
    }

    /// Build the full multi-line sequence.
    std::vector<std::string> build() const {
        std::vector<std::string> result;
        // Start line
        result.push_back(NumericBuilder::raw(start_num_, server_, target_,
                                             ":- " + server_ + " Message of the day - "));
        // Content lines
        for (auto& line : lines_) {
            result.push_back(NumericBuilder::raw(line_num_, server_, target_,
                                                 ":- " + line));
        }
        // End line
        result.push_back(NumericBuilder::raw(end_num_, server_, target_,
                                             ":End of message"));
        return result;
    }

    /// Build only the content lines + end (no start header).
    std::vector<std::string> build_simple() const {
        std::vector<std::string> result;
        for (auto& line : lines_) {
            result.push_back(NumericBuilder::raw(line_num_, server_, target_,
                                                 ":" + line));
        }
        result.push_back(NumericBuilder::raw(end_num_, server_, target_,
                                             ":End of list"));
        return result;
    }

private:
    uint16_t line_num_, start_num_, end_num_;
    std::string server_, target_;
    std::vector<std::string> lines_;
};

// ============================================================================
// SECTION 29 : Connection registration helpers
// ============================================================================

/// @brief Connection registration state.
enum class RegistrationState : uint8_t {
    kNone        = 0,
    kGotPass     = 1,
    kGotNick     = 2,
    kGotUser     = 4,
    kRegistered  = 8,   // kGotNick | kGotUser
};

inline bool is_registered(RegistrationState s) {
    return (static_cast<uint8_t>(s) & static_cast<uint8_t>(RegistrationState::kRegistered))
           == static_cast<uint8_t>(RegistrationState::kRegistered);
}

inline bool has_nick(RegistrationState s) {
    return (static_cast<uint8_t>(s) & static_cast<uint8_t>(RegistrationState::kGotNick)) != 0;
}

inline bool has_user(RegistrationState s) {
    return (static_cast<uint8_t>(s) & static_cast<uint8_t>(RegistrationState::kGotUser)) != 0;
}

/// @brief Server-side connection tracking for the link protocol.
struct ConnectionInfo {
    std::string          server_name;
    std::string          sid;
    int                  hopcount        = 0;
    ServerLinkState      link_state      = ServerLinkState::kDisconnected;
    ProtoCtl             proto;
    bool                 incoming        = false;
    time_t               connected_at    = 0;
    std::string          remote_address;

    // For user connections
    std::string          nick;
    std::string          user;
    std::string          host;
    std::string          realname;
    std::string          account;
    RegistrationState    reg_state       = RegistrationState::kNone;
    CapManager           caps;
    SASLSession          sasl;
    TokenBucket          flood_bucket{4.0, 10.0};  // 4 msg/sec, burst 10

    bool is_server_link() const {
        return link_state >= ServerLinkState::kWaitServer;
    }
    bool is_linked() const {
        return link_state == ServerLinkState::kLinked;
    }
};

/// @brief Build the initial PASS/SERVER handshake for outbound links.
inline std::string outbound_link_handshake(const std::string& password,
                                           const std::string& server_name,
                                           const std::string& info) {
    std::ostringstream oss;
    if (!password.empty()) oss << "PASS " << password << " TS 6\r\n";
    oss << "CAPAB :" << ProtoCtl().serialize() << "\r\n";
    oss << "SERVER " << server_name << " 1 :" << info << "\r\n";
    return oss.str();
}

// ============================================================================
// SECTION 30 : Channel membership tracking helpers
// ============================================================================

/// @brief Membership prefix information for multi-prefix and NAMES replies.
struct MembershipPrefix {
    char mode_char;   // 'q','a','o','h','v'
    char prefix_char; // '~','&','@','%','+'

    static std::vector<MembershipPrefix> standard_prefixes() {
        return {
            {'q', '~'},  // founder
            {'a', '&'},  // protected/admin
            {'o', '@'},  // operator
            {'h', '%'},  // half-op
            {'v', '+'},  // voice
        };
    }

    /// Convert a mode string (e.g. "+ov") to prefix string (e.g. "@+").
    static std::string modes_to_prefixes(const std::string& modes) {
        std::string result;
        auto stdpref = standard_prefixes();
        for (char m : modes) {
            for (auto& sp : stdpref) {
                if (sp.mode_char == m) {
                    result += sp.prefix_char;
                    break;
                }
            }
        }
        return result;
    }

    /// Convert a prefix string (e.g. "@+") to mode string (e.g. "ov").
    static std::string prefixes_to_modes(const std::string& prefixes) {
        std::string result;
        auto stdpref = standard_prefixes();
        for (char p : prefixes) {
            for (auto& sp : stdpref) {
                if (sp.prefix_char == p) {
                    result += sp.mode_char;
                    break;
                }
            }
        }
        return result;
    }

    /// Sort prefix chars in order of rank (highest first).
    static std::string sort_prefixes(const std::string& prefixes) {
        std::string sorted;
        const char* rank = "~&@%+";
        for (const char* r = rank; *r; ++r) {
            if (prefixes.find(*r) != std::string::npos)
                sorted += *r;
        }
        return sorted;
    }
};

// ============================================================================
// SECTION 31 : Server info string builder
// ============================================================================

/// @brief Generate the full RPL_MYINFO line.
inline std::string myinfo_reply(const std::string& server, const std::string& nick,
                                const std::string& server_name,
                                const std::string& version,
                                const std::string& user_modes,
                                const std::string& chan_modes) {
    std::ostringstream oss;
    oss << ':' << server << " 004 " << nick << ' '
        << server_name << ' ' << version << ' '
        << user_modes << ' ' << chan_modes;
    return oss.str();
}

// ============================================================================
// SECTION 32 : STATS helpers
// ============================================================================

/// @brief Build a STATS response line.
inline std::string stats_reply(const std::string& server, const std::string& nick,
                               char stats_type, const std::string& params) {
    uint16_t numeric = 0;
    switch (stats_type) {
        case 'l': numeric = 211; break;  // RPL_STATSLINKINFO
        case 'c': case 'm': numeric = 212; break;  // RPL_STATSCOMMANDS
        case 'o': numeric = 243; break;  // RPL_STATSOLINE
        case 'u': numeric = 242; break;  // RPL_STATSUPTIME
        default:  numeric = 211; break;
    }

    std::ostringstream oss;
    oss << ':' << server << ' ' << std::setfill('0') << std::setw(3)
        << numeric << ' ' << nick << ' ' << params;
    return oss.str();
}

// ============================================================================
// SECTION 33 : Listening / connection configuration
// ============================================================================

/// @brief Listener configuration for the progressive server.
struct ListenerConfig {
    std::string  address;
    uint16_t     port       = 6667;
    bool         tls        = false;
    std::string  tls_cert_file;
    std::string  tls_key_file;
    int          max_clients = 1024;

    std::string to_string() const {
        std::ostringstream oss;
        oss << (tls ? "tls://" : "tcp://") << address << ':' << port;
        if (max_clients > 0) oss << " max=" << max_clients;
        return oss.str();
    }
};

/// @brief Server link configuration for outgoing connections.
struct LinkConfig {
    std::string  name;         // remote server name
    std::string  host;
    uint16_t     port       = 7000;
    std::string  password;
    bool         auto_connect = false;
    ProtoCtl     proto;

    std::string to_string() const {
        std::ostringstream oss;
        oss << name << '@' << host << ':' << port;
        if (auto_connect) oss << " [auto]";
        return oss.str();
    }
};

// ============================================================================
// SECTION 34 : Utility: escape/unescape for IRC format codes
// ============================================================================

/// @brief Strip IRC formatting codes (bold, color, italic, etc.).
inline std::string strip_formatting(const std::string& input) {
    std::string out;
    out.reserve(input.size());
    size_t i = 0;
    while (i < input.size()) {
        char c = input[i];
        // IRC formatting: \x02 (bold), \x03 (color), \x0F (reset),
        //                 \x16 (reverse), \x1D (italic), \x1E (strikethrough),
        //                 \x1F (underline), \x11 (monospace)
        if (c == '\x02' || c == '\x0F' || c == '\x16' ||
            c == '\x1D' || c == '\x1E' || c == '\x1F' || c == '\x11') {
            ++i;
            continue;
        }
        if (c == '\x03') {
            // Color code: \x03[fg][,bg]
            ++i;
            // Skip digits and comma
            while (i < input.size() && isdigit(input[i])) ++i;
            if (i < input.size() && input[i] == ',') {
                ++i;
                while (i < input.size() && isdigit(input[i])) ++i;
            }
            continue;
        }
        out.push_back(c);
        ++i;
    }
    return out;
}

// ============================================================================
// SECTION 35 : Thread-safe message queue
// ============================================================================

/// @brief A simple thread-safe queue for outgoing IRC messages.
template <typename T>
class TSQueue {
public:
    void push(const T& item) {
        std::lock_guard<std::mutex> lk(mtx_);
        queue_.push_back(item);
    }

    void push(T&& item) {
        std::lock_guard<std::mutex> lk(mtx_);
        queue_.push_back(std::move(item));
    }

    bool pop(T& item) {
        std::lock_guard<std::mutex> lk(mtx_);
        if (queue_.empty()) return false;
        item = std::move(queue_.front());
        queue_.pop_front();
        return true;
    }

    bool try_pop_all(std::vector<T>& out) {
        std::lock_guard<std::mutex> lk(mtx_);
        if (queue_.empty()) return false;
        out.assign(std::make_move_iterator(queue_.begin()),
                   std::make_move_iterator(queue_.end()));
        queue_.clear();
        return true;
    }

    size_t size() const {
        std::lock_guard<std::mutex> lk(mtx_);
        return queue_.size();
    }

    bool empty() const {
        std::lock_guard<std::mutex> lk(mtx_);
        return queue_.empty();
    }

    void clear() {
        std::lock_guard<std::mutex> lk(mtx_);
        queue_.clear();
    }

private:
    mutable std::mutex mtx_;
    std::deque<T> queue_;
};

/// @brief Outgoing message queue specialized for IRC lines.
class OutgoingMessageQueue {
public:
    /// Enqueue a raw line (without CRLF — append_crlf is called on drain).
    void enqueue(const std::string& line) {
        queue_.push(line);
    }

    /// Enqueue a numeric reply.
    void enqueue_numeric(uint16_t numeric, const std::string& server,
                         const std::string& target, const std::string& suffix) {
        queue_.push(NumericBuilder::raw(numeric, server, target, suffix));
    }

    /// Drain all messages into a vector, each with CRLF appended.
    std::vector<std::string> drain() {
        std::vector<std::string> raw;
        queue_.try_pop_all(raw);
        std::vector<std::string> result;
        result.reserve(raw.size());
        for (auto& line : raw) {
            result.push_back(append_crlf(line));
        }
        return result;
    }

    /// Drain into a single buffer (for send()).
    std::string drain_buffer() {
        std::vector<std::string> lines = drain();
        std::ostringstream oss;
        for (auto& line : lines) oss << line;
        return oss.str();
    }

    size_t pending() const { return queue_.size(); }

private:
    TSQueue<std::string> queue_;
};

// ============================================================================
// SECTION 36 : WHOIS response builder (complete)
// ============================================================================

/// @brief Build a complete WHOIS response.
class WhoisBuilder {
public:
    WhoisBuilder(const std::string& server, const std::string& target_nick,
                 const std::string& whois_nick, const std::string& whois_user,
                 const std::string& whois_host, const std::string& whois_realname,
                 const std::string& whois_server_name, const std::string& whois_server_info)
        : server_(server), target_(target_nick),
          whois_nick_(whois_nick), whois_user_(whois_user),
          whois_host_(whois_host), whois_realname_(whois_realname),
          whois_server_name_(whois_server_name),
          whois_server_info_(whois_server_info) {}

    void set_account(const std::string& account) { account_ = account; }
    void set_idle(time_t signon) { signon_time_ = signon; }
    void set_oper(bool oper) { is_oper_ = oper; }
    void set_secure(bool sec) { is_secure_ = sec; }
    void set_away(const std::string& msg) { away_msg_ = msg; is_away_ = true; }
    void add_channel(const std::string& chan_with_prefix) {
        channels_.push_back(chan_with_prefix);
    }
    void set_certfp(const std::string& fp) { certfp_ = fp; }
    void set_connect_info(const std::string& ident, const std::string& host) {
        connect_ident_ = ident;
        connect_host_  = host;
    }

    /// Build the complete sequence of WHOIS replies.
    std::vector<std::string> build() const {
        std::vector<std::string> result;
        time_t now = time(nullptr);

        // RPL_WHOISUSER
        result.push_back(NumericBuilder::from_table(311, server_, target_,
            {whois_nick_, whois_user_, whois_host_, whois_realname_}));

        // RPL_WHOISCHANNELS
        if (!channels_.empty()) {
            std::ostringstream chans;
            for (size_t i = 0; i < channels_.size(); ++i) {
                if (i > 0) chans << ' ';
                chans << channels_[i];
            }
            result.push_back(NumericBuilder::raw(319, server_, target_,
                whois_nick_ + " :" + chans.str()));
        }

        // RPL_WHOISSERVER
        result.push_back(NumericBuilder::from_table(312, server_, target_,
            {whois_nick_, whois_server_name_, whois_server_info_}));

        // RPL_WHOISOPERATOR (if oper)
        if (is_oper_) {
            result.push_back(NumericBuilder::raw(313, server_, target_,
                whois_nick_ + " :is an IRC operator"));
        }

        // RPL_WHOISIDLE
        if (signon_time_ > 0) {
            time_t idle = now - signon_time_;
            if (idle < 0) idle = 0;
            result.push_back(NumericBuilder::from_table(317, server_, target_,
                {whois_nick_,
                 std::to_string(static_cast<unsigned long>(idle)),
                 std::to_string(static_cast<long>(signon_time_))}));
        }

        // RPL_WHOISACCOUNT
        if (!account_.empty()) {
            result.push_back(NumericBuilder::raw(330, server_, target_,
                whois_nick_ + " " + account_ + " :is logged in as"));
        }

        // RPL_WHOISSECURE (if using TLS)
        if (is_secure_) {
            result.push_back(NumericBuilder::raw(671, server_, target_,
                whois_nick_ + " :is using a secure connection"));
        }

        // RPL_WHOISCERTFP
        if (!certfp_.empty()) {
            result.push_back(NumericBuilder::raw(276, server_, target_,
                whois_nick_ + " :has client certificate fingerprint " + certfp_));
        }

        // RPL_WHOISHOST (actual host)
        if (!connect_ident_.empty()) {
            result.push_back(NumericBuilder::raw(378, server_, target_,
                whois_nick_ + " :is connecting from " + connect_ident_ + "@" +
                connect_host_ + " " + connect_host_));
        }

        // RPL_AWAY (if away)
        if (is_away_) {
            result.push_back(NumericBuilder::raw(301, server_, target_,
                whois_nick_ + " :" + away_msg_));
        }

        // RPL_ENDOFWHOIS
        result.push_back(NumericBuilder::raw(318, server_, target_,
            whois_nick_ + " :End of WHOIS list"));

        return result;
    }

private:
    std::string server_, target_;
    std::string whois_nick_, whois_user_, whois_host_, whois_realname_;
    std::string whois_server_name_, whois_server_info_;
    std::string account_, away_msg_, certfp_;
    std::string connect_ident_, connect_host_;
    time_t signon_time_ = 0;
    bool is_oper_  = false;
    bool is_secure_ = false;
    bool is_away_  = false;
    std::vector<std::string> channels_;
};

// ============================================================================
// SECTION 37 : Netburst orchestrator
// ============================================================================

/// @brief Netburst orchestrator — drives the full server burst sequence.
class NetburstOrchestrator {
public:
    /// Generate the complete sequence of messages to burst to a newly-linked
    /// server. This is called on the linking server side.
    struct BurstContext {
        std::string local_server_name;
        std::string local_sid;
        std::string remote_sid;
        bool use_sid_uid = false;

        std::vector<ServerBurst::BurstUser> users;
        // channel -> {ts, modes, members}
        struct ChannelInfo {
            time_t ts = 0;
            std::string modes;
            std::vector<std::string> members; // prefixed (e.g. "@nick")
            std::string topic;
            std::string topic_setter;
            time_t topic_ts = 0;
            std::vector<std::string> bans;
            std::vector<std::string> excepts;
            std::vector<std::string> invexs;
        };
        std::unordered_map<std::string, ChannelInfo> channels;
    };

    /// Build the full burst sequence.
    static std::vector<std::string> build_burst(const BurstContext& ctx) {
        std::vector<std::string> result;

        // 1. Burst all users
        for (auto& u : ctx.users) {
            result.push_back(ServerBurst::user_burst_line(ctx.local_sid, u, ctx.use_sid_uid));
        }

        // 2. Burst all channels (SJOIN + optional TMODE/BMASK)
        for (auto& kv : ctx.channels) {
            auto& ch = kv.second;

            // SJOIN
            result.push_back(ServerBurst::sjoin_line(
                ctx.local_sid, ch.ts, kv.first, ch.modes, ch.members));

            // Topic
            if (!ch.topic.empty()) {
                result.push_back(ts6::tmode(ctx.local_sid, ch.ts, kv.first,
                                            ch.topic_setter, ch.topic_ts, ch.topic));
            }

            // Bans
            if (!ch.bans.empty()) {
                result.push_back(ts6::bmask(ctx.local_sid, ch.ts, kv.first, 'b', ch.bans));
            }
            if (!ch.excepts.empty()) {
                result.push_back(ts6::bmask(ctx.local_sid, ch.ts, kv.first, 'e', ch.excepts));
            }
            if (!ch.invexs.empty()) {
                result.push_back(ts6::bmask(ctx.local_sid, ch.ts, kv.first, 'I', ch.invexs));
            }
        }

        // 3. End-of-burst
        result.push_back(ts6::eob(ctx.local_sid));

        return result;
    }
};

// ============================================================================
// SECTION 38 : Server operator (OPER) handling
// ============================================================================

/// @brief Oper block configuration.
struct OperBlock {
    std::string name;
    std::string password_hash;
    std::string host_mask;
    std::string oper_class;   // e.g. "NetAdmin", "GlobalOp", "LocalOp"
    std::vector<std::string> flags;  // individual oper flags

    /// Check if a user@host matches this oper block.
    bool matches(const std::string& userhost) const {
        return mask_match(host_mask, userhost);
    }
};

/// @brief Oper privilege flags.
enum class OperFlag : uint64_t {
    kCanKill         = 0,
    kCanGLine        = 1,
    kCanKLine        = 2,
    kCanZLine        = 3,
    kCanGZLine       = 4,
    kCanDie          = 5,
    kCanRestart      = 6,
    kCanRehash       = 7,
    kCanSet          = 8,
    kCanSeeOper      = 9,
    kCanSeeHidden    = 10,
    kCanOverride     = 11,  // walk through modes/bans/etc
    kCanJoinBanned   = 12,
    kCanSajoin       = 13,
    kCanSamode       = 14,
    kCanSakick       = 15,
    kCanSanick       = 16,
    kCanSapart       = 17,
    kCanSquit        = 18,
    kCanConnect      = 19,
    kCanDccDeny      = 20,
    kCanAddLine      = 21,
    kCanChgHost      = 22,
    kCanSetHost      = 23,
    kCanChgIdent     = 24,
    kCanVHost        = 25,
    kCanHide         = 26,
    kCanOperModes    = 27,
    kMaxCount
};

constexpr const char* kOperFlagNames[] = {
    "can_kill", "can_gline", "can_kline", "can_zline", "can_gzline",
    "can_die", "can_restart", "can_rehash", "can_set", "can_see_oper",
    "can_see_hidden", "can_override", "can_join_banned", "can_sajoin",
    "can_samode", "can_sakick", "can_sanick", "can_sapart", "can_squit",
    "can_connect", "can_dccdeny", "can_addline", "can_chghost",
    "can_sethost", "can_chgident", "can_vhost", "can_hide", "can_oper_modes"
};

static_assert(sizeof(kOperFlagNames) / sizeof(kOperFlagNames[0]) ==
              static_cast<size_t>(OperFlag::kMaxCount),
              "Oper flag name table mismatch");

/// @brief Oper flag set.
class OperFlagSet {
public:
    void set(OperFlag f) { flags_.set(static_cast<size_t>(f)); }
    bool has(OperFlag f) const { return flags_.test(static_cast<size_t>(f)); }
    void parse_names(const std::vector<std::string>& names) {
        for (auto& n : names) {
            for (size_t i = 0; i < static_cast<size_t>(OperFlag::kMaxCount); ++i) {
                if (n == kOperFlagNames[i]) {
                    flags_.set(i);
                    break;
                }
            }
        }
    }
    std::vector<std::string> to_names() const {
        std::vector<std::string> result;
        for (size_t i = 0; i < static_cast<size_t>(OperFlag::kMaxCount); ++i) {
            if (flags_.test(i)) result.push_back(kOperFlagNames[i]);
        }
        return result;
    }
private:
    std::bitset<static_cast<size_t>(OperFlag::kMaxCount)> flags_;
};

// ============================================================================
// SECTION 39 : Server configuration aggregator
// ============================================================================

/// @brief Complete server configuration.
struct ServerConfig {
    std::string server_name;
    std::string server_info;
    std::string server_sid;
    std::string network_name       = "ProgressiveNet";
    int         max_clients        = 1024;
    int         max_channels       = 100;
    int         ping_freq          = 120;
    int         max_sendq          = 300000;
    CaseMapping case_mapping       = CaseMapping::kRfc1459;
    ChanModes   chan_modes         = ChanModes::defaults();
    std::string user_modes         = "iowghraAsNO";
    std::string default_umodes     = "i";
    bool        use_sid_uid        = true;
    int         nick_len           = 30;
    int         channel_len        = 64;
    int         topic_len          = 390;
    bool        enable_sasl        = true;
    bool        enable_sts         = false;
    STSPolicy   sts_policy;

    std::vector<ListenerConfig>    listeners;
    std::vector<LinkConfig>        links;
    std::vector<OperBlock>         opers;

    /// Build the complete ISUPPORT string.
    std::string isupport(const std::string& nick) const {
        ISupportBuilder b;
        b.set("NETWORK",       network_name);
        b.set("NICKLEN",       std::to_string(nick_len));
        b.set("CHANNELLEN",    std::to_string(channel_len));
        b.set("TOPICLEN",      std::to_string(topic_len));
        b.set("CHANMODES",     chan_modes.to_string());
        b.set("PREFIX",        "(qaohv)~&@%+");
        b.set("STATUSMSG",     "~&@%+");
        b.set("CASEMAPPING",   CaseMapRegistry::to_isupport(case_mapping));
        b.set("MODES",         "20");
        b.set("MAXLIST",       "beI:50");
        b.set("ELIST",         "U");
        b.set("SILENCE",       "50");
        b.set("MONITOR",       "100");
        b.set("WHOX",          "");
        b.set("CLIENTVER",     "3.0");
        b.set("SAFELIST",      "");
        b.set("FNC",           "");
        b.set("KNOCK",         "");
        b.set("INVEX",         "");
        b.set("EXCEPTS",       "");
        b.set("UTF8ONLY",      "");
        b.set("CPRIVMSG",      "");
        b.set("CNOTICE",       "");
        return b.build(server_name, nick);
    }
};

// ============================================================================
// SECTION 40 : Debug / logging extension
// ============================================================================

/// @brief Simple protocol debug logger.
class ProtocolLogger {
public:
    enum class Level : uint8_t {
        kDebug   = 0,
        kInfo    = 1,
        kWarning = 2,
        kError   = 3,
    };

    using LogCallback = std::function<void(Level, const std::string&)>;

    void set_callback(LogCallback cb) { callback_ = std::move(cb); }

    void log(Level lvl, const std::string& msg) {
        if (callback_) callback_(lvl, msg);
    }

    void debug(const std::string& msg)   { log(Level::kDebug,   msg); }
    void info(const std::string& msg)    { log(Level::kInfo,    msg); }
    void warn(const std::string& msg)    { log(Level::kWarning, msg); }
    void error(const std::string& msg)   { log(Level::kError,   msg); }

    void log_parsed_message(const ParsedMessage& pm, bool incoming) {
        std::ostringstream oss;
        oss << (incoming ? "RECV" : "SEND") << " [" << pm.command << "]";
        if (!pm.prefix.empty()) oss << " from=" << pm.prefix;
        oss << " tags=" << pm.tags.size()
            << " params=" << pm.params.size()
            << " trail=" << pm.has_trailing;
        for (auto& p : pm.params) oss << " '" << p << "'";
        if (pm.has_trailing) oss << " :'" << pm.trailing << "'";
        debug(oss.str());
    }

private:
    LogCallback callback_;
};

} // namespace irc
} // namespace progressive
