#!/usr/bin/env perl
# Guard against silent argument drops in the frontend's own helpers.
#
#   perl tests/check-call-arity.pl frontend/assets/*.js
#
# For every `const NAME = (a, b, c) =>` defined at file scope this walks all
# unqualified `NAME(...)` call sites, counts the arguments at nesting depth 0
# and reports a mismatch.
#
# Why this earns its lines: a helper called with one argument too few does not
# raise anything. JavaScript simply binds the missing parameter to
# `undefined`, `JSON.stringify(undefined)` yields no body at all, and the
# server answers 400 - which is exactly how `jsonCall(method, url, payload)`
# shipped with every call site passing only two arguments, taking the whole
# encryption UI down while every syntax check still passed.
use strict;
use warnings;

# ---- helpers ----------------------------------------------------------

# Strip strings, template literals and line comments so that brackets inside
# them cannot skew the depth count.
sub scrub {
    my ($s) = @_;
    $s =~ s{("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`)}{""}gs;
    $s =~ s{//[^\n]*}{}g;
    return $s;
}

# Find the index of the parenthesis closing the one at $open, in $s.
sub match_paren {
    my ($s, $open) = @_;
    my $depth = 0;
    for (my $i = $open; $i < length($s); $i++) {
        my $c = substr($s, $i, 1);
        if ($c eq '"' || $c eq "'" || $c eq '`') {
            my $q = $c;
            $i++;
            while ($i < length($s)) {
                my $d = substr($s, $i, 1);
                last if $d eq $q;
                $i++ if $d eq '\\';
                $i++;
            }
        } elsif ($c eq '/' && substr($s, $i, 2) eq '//') {
            my $nl = index($s, "\n", $i);
            return undef if $nl < 0;
            $i = $nl;
        } elsif ($c eq '(') {
            $depth++;
        } elsif ($c eq ')') {
            $depth--;
            return $i if $depth == 0;
        }
    }
    return undef;
}

# How many arguments are written between $open and its partner.
sub arg_count {
    my ($s, $open) = @_;
    my $close = match_paren($s, $open);
    return undef unless defined $close;
    my $inner = substr($s, $open + 1, $close - $open - 1);
    $inner = scrub($inner);
    $inner =~ s/^\s+|\s+$//g;
    return 0 if $inner eq '';
    my $depth = 0;
    my $commas = 0;
    foreach my $c (split //, $inner) {
        $depth++ if $c =~ /[(\[{]/;
        $depth-- if $c =~ /[)\]}]/;
        $commas++ if $c eq ',' && $depth == 0;
    }
    return $commas + 1;
}

sub line_of {
    my ($s, $idx) = @_;
    return 1 + (substr($s, 0, $idx) =~ tr/\n//);
}

# ---- scan -------------------------------------------------------------

my $problems = 0;

foreach my $file (@ARGV) {
    open my $fh, '<', $file or die "cannot read $file: $!";
    local $/;
    my $src = <$fh>;
    close $fh;

    my %def;    # name -> { pos =>, want => }
    while ($src =~ /const\s+(\w+)\s*=\s*(?:async\s*)?\(/g) {
        my $name  = $1;
        my $open  = index($src, '(', $-[0]);
        next if $open < 0;
        my $close = match_paren($src, $open);
        next unless defined $close;
        my $params = substr($src, $open + 1, $close - $open - 1);
        $params =~ s/^\s+|\s+$//g;
        my $want = $params eq '' ? 0 : scalar(split /,/, $params);
        $def{$name} = { pos => $-[1], want => $want };   # $-[1] = name's own offset
    }

    foreach my $name (sort keys %def) {
        my $want   = $def{$name}{want};
        my $origin = $def{$name}{pos};
        pos($src) = 0;
        while ($src =~ /\b\Q$name\E\s*\(/g) {
            my $at = $-[0];
            next if $at == $origin;                       # the definition itself
            next if $at > 0 && substr($src, $at - 1, 1) eq '.';   # obj.NAME()
            next if $at > 0 && substr($src, $at - 1, 1) =~ /\w/;  # part of a word
            my $open = index($src, '(', $at);
            my $got  = arg_count($src, $open);
            next unless defined $got;
            next if $got == $want;
            printf "%s:%d: %s takes %d arg%s, call passes %d\n",
                $file, line_of($src, $at), $name, $want,
                $want == 1 ? '' : 's', $got;
            $problems++;
        }
    }
}

exit($problems ? 1 : 0);
