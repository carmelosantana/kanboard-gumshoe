<?php

namespace Kanboard\Plugin\Gumshoe\Run;

final readonly class Jobs
{
    public const INVENTORY = 'gumshoe.inventory';
    public const RECHECK = 'gumshoe.osv-recheck';
    public const BUDGET = 10;
    public const INTERVALS = [self::INVENTORY => 86400, self::RECHECK => 3600];

    public function __construct(private Scanner $scanner)
    {
    }

    public function descriptors(): array
    {
        $jobs = [];
        foreach (self::INTERVALS as $id => $interval) {
            $jobs[] = [
                'id' => $id,
                'plugin' => 'Gumshoe',
                'interval' => $interval,
                'budget' => self::BUDGET,
                'run' => fn (int $deadline): array => $this->scanner->tick($id, 'foreman', $deadline),
            ];
        }
        return $jobs;
    }
}
