<?php

namespace Kanboard\Plugin\Gumshoe\Advisory;

use InvalidArgumentException;

final class Priority
{
    public static function of(array $group): string
    {
        if (!empty($group['malware']) || !empty($group['kev'])) {
            return 'urgent';
        }

        $score = $group['cvss_max'] ?? null;
        return match (true) {
            $score === null => 'normal',
            $score >= 7.0 => 'high',
            $score >= 4.0 => 'normal',
            default => 'low',
        };
    }

    public static function toProject(string $priority, int $start, int $end): int
    {
        $step = match ($priority) {
            'low' => 0,
            'normal' => 1,
            'high' => 2,
            'urgent' => 3,
            default => throw new InvalidArgumentException('Unknown Gumshoe priority.'),
        };

        return $start + (int) round(($end - $start) * ($step / 3));
    }
}
