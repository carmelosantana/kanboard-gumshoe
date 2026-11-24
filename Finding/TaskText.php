<?php

namespace Kanboard\Plugin\Gumshoe\Finding;

use Kanboard\Plugin\Gumshoe\Secrets\Redactor;

final class TaskText
{
    public static function title(string $package, string $primaryId, int $repos): string
    {
        $noun = $repos === 1 ? 'repo' : 'repos';

        return self::label("[Gumshoe] $package — $primaryId ($repos $noun)");
    }

    public static function label(string $value): string
    {
        return trim(preg_replace('/[\x00-\x20\x7f]+/', ' ', Redactor::redact($value)));
    }

    /** @param list<array{repo: string, path: string, version: string, scope: string}> $exposures */
    public static function description(string $summary, array $ids, array $exposures, bool $malware = false, bool $kev = false): string
    {
        $sections = [];
        if ($summary !== '') {
            $sections[] = self::markdown(mb_substr(Redactor::redact($summary), 0, 2000));
        }

        $flags = array_filter([$malware ? 'Known malware' : '', $kev ? 'Listed in CISA KEV' : '']);
        if ($flags !== []) {
            $sections[] = implode(' · ', $flags);
        }

        $links = [];
        foreach (array_unique($ids) as $id) {
            $base = match (true) {
                preg_match('/\ACVE-[0-9]{4}-[0-9]{4,}\z/', $id) === 1 => 'https://nvd.nist.gov/vuln/detail/',
                preg_match('/\AGHSA-(?:[23456789cfghjmpqrvwx]{4}-){2}[23456789cfghjmpqrvwx]{4}\z/', $id) === 1 => 'https://github.com/advisories/',
                preg_match('/\A(?:OSV|MAL|PYSEC|RUSTSEC|GO|GSD|OSVDB|PACKAGIST|PKSA|BIT|DSA|DLA|RHSA|USN|ALSA|ALBA|ALAS|SUSE|ECHO)-[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*\z/', $id) === 1 => 'https://osv.dev/vulnerability/',
                default => null,
            };
            if ($base !== null) {
                $links[] = "[$id]($base$id)";
            }
        }
        if ($links !== []) {
            $sections[] = implode(' · ', $links);
        }

        if ($exposures !== []) {
            usort($exposures, static fn (array $a, array $b): int => [$a['path'], $a['repo'], $a['version'], $a['scope']]
                <=> [$b['path'], $b['repo'], $b['version'], $b['scope']]);
            $lines = ['| Repository | Path | Version | Scope |', '| --- | --- | --- | --- |'];
            foreach ($exposures as $row) {
                $cells = array_map(self::markdown(...), [$row['repo'], $row['path'], $row['version'], $row['scope']]);
                $lines[] = '| '.implode(' | ', $cells).' |';
            }
            $sections[] = implode("\n", $lines);
        }

        return implode("\n\n", $sections);
    }

    public static function repoInComment(string $name): string
    {
        return preg_match('~\A[A-Za-z0-9-]+/[A-Za-z0-9_.-]+\z~', $name) === 1 ? $name : self::markdown($name);
    }

    private static function markdown(string $text): string
    {
        // Named entities stay literal in Kanboard's Markdown extensions.
        // Numeric entities would expose their # to Kanboard's task matcher.
        return preg_replace_callback(
            '/[\x21-\x2f\x3a-\x40\x5b-\x60\x7b-\x7d]|~+/',
            static fn (array $part): string => $part[0][0] === '~' ? '`'.$part[0].'`'
                : str_replace('-', '\-', htmlentities($part[0], ENT_QUOTES | ENT_HTML5, 'UTF-8')),
            self::label($text),
        );
    }
}
