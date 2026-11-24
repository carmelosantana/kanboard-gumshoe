<?php

namespace Kanboard\Plugin\Gumshoe\Watch;

final readonly class WatchRules
{
    public function __construct(private array $settings, private int $now)
    {
    }

    public function watched(array $owner, array $repo): bool
    {
        $reason = $this->reason($owner, $repo);
        return $reason === 'pinned' || str_starts_with($reason, 'pushed ');
    }

    public function reason(array $owner, array $repo): string
    {
        $pushedAt = $repo['pushed_at'] ?? null;
        $age = max(0, $this->now - (int) $pushedAt);
        $days = intdiv($age, 86400);

        return match (true) {
            ($repo['gone_at'] ?? null) !== null => '',
            !(bool) $owner['enabled'] => 'owner off',
            $repo['mode'] === 'exclude' => 'excluded',
            $repo['mode'] === 'pin' => 'pinned',
            (bool) $repo['fork'] && !(bool) $this->settings['forks'] => 'fork',
            (bool) $repo['archived'] && !(bool) $this->settings['archived'] => 'archived',
            $pushedAt !== null && $age <= (int) $this->settings['window_days'] * 86400 => "pushed {$days}d ago",
            default => "idle {$days}d",
        };
    }
}
