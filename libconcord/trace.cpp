/*
 * vim:tw=80:ai:tabstop=4:softtabstop=4:shiftwidth=4:expandtab
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*
 * The trace: the last debug() lines, kept so a program can show what led up to
 * an error. A GUI has no stderr to read, and a remote nobody here owns can
 * only be debugged from what its owner sends back.
 */

#include <stdarg.h>
#include <stdio.h>
#include <string>
#include "libconcord.h"
#include "lc_internal.h"

/* Enough for a whole get_identity() and what came before it. */
static const unsigned int TRACE_LINES = 200;
static const unsigned int TRACE_LINE_LENGTH = 240;

static std::string trace_lines[TRACE_LINES];
static unsigned int trace_next = 0;     // where the next line goes
static unsigned int trace_count = 0;
static std::string trace_text;

void lc_trace(const char *function, const char *format, ...)
{
    char line[TRACE_LINE_LENGTH];
    int n = snprintf(line, sizeof(line), "%s: ", function);
    if (n < 0 || n >= (int)sizeof(line))
        n = 0;
    va_list args;
    va_start(args, format);
    vsnprintf(line + n, sizeof(line) - n, format, args);
    va_end(args);
#ifdef _DEBUG
    fprintf(stderr, "DEBUG (%s\n", line);
#endif
    trace_lines[trace_next] = line;
    trace_next = (trace_next + 1) % TRACE_LINES;
    if (trace_count < TRACE_LINES)
        trace_count++;
}

const char *lc_get_trace()
{
    trace_text.clear();
    unsigned int first = (trace_next + TRACE_LINES - trace_count) % TRACE_LINES;
    for (unsigned int i = 0; i < trace_count; i++) {
        trace_text += trace_lines[(first + i) % TRACE_LINES];
        trace_text += '\n';
    }
    return trace_text.c_str();
}

void lc_clear_trace()
{
    trace_next = 0;
    trace_count = 0;
    trace_text.clear();
}
