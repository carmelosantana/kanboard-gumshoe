<?php

namespace Kanboard\Plugin\Gumshoe\Run;

use Closure;
use LogicException;
use PDO;
use Throwable;

final readonly class WriterLease
{
    private Closure $clock;

    public function __construct(private PDO $pdo, ?Closure $clock = null)
    {
        $this->clock = $clock ?? time(...);
    }

    public function claim(string $holder, int $ttl): bool
    {
        $now = ($this->clock)();
        $statement = $this->pdo->prepare(
            "UPDATE gumshoe_state SET holder = ?, lease_until = ?
             WHERE name = 'writer' AND (lease_until < ? OR holder = ?)"
        );
        $statement->execute([$holder, $now + $ttl, $now, $holder]);
        return $statement->rowCount() === 1;
    }

    public function renew(string $holder, int $ttl): bool
    {
        $now = ($this->clock)();
        $until = $now + $ttl;
        $statement = $this->pdo->prepare(
            "UPDATE gumshoe_state SET lease_until = ?
             WHERE name = 'writer' AND holder = ? AND lease_until >= ?"
        );
        $statement->execute([$until, $holder, $now]);
        if ($statement->rowCount() === 1) {
            return true;
        }

        // MariaDB can report zero changed rows when renewing in the same second.
        $same = $this->pdo->prepare("SELECT 1 FROM gumshoe_state WHERE name = 'writer' AND holder = ? AND lease_until = ?");
        $same->execute([$holder, $until]);
        return $same->fetchColumn() !== false;
    }

    public function release(string $holder): bool
    {
        $statement = $this->pdo->prepare(
            "UPDATE gumshoe_state SET holder = NULL, lease_until = 0 WHERE name = 'writer' AND holder = ?"
        );
        $statement->execute([$holder]);
        return $statement->rowCount() === 1;
    }

    /** Lock the writer row until this transaction commits. A stale holder cannot enter a batch. */
    public function assertHolder(string $holder): void
    {
        if (!$this->pdo->inTransaction()) {
            throw new LogicException('The writer fence requires an active transaction.');
        }
        $this->pdo->exec("UPDATE gumshoe_state SET lease_until = lease_until WHERE name = 'writer'");
        $row = $this->pdo->query("SELECT holder, lease_until FROM gumshoe_state WHERE name = 'writer'")->fetch(PDO::FETCH_ASSOC);
        if ($row === false || $row['holder'] !== $holder || (int) $row['lease_until'] < ($this->clock)()) {
            throw new LeaseLost();
        }
    }

    public function write(string $holder, callable $batch): mixed
    {
        $this->pdo->beginTransaction();
        try {
            $this->assertHolder($holder);
            $result = $batch();
            $this->pdo->commit();
            return $result;
        } catch (Throwable $failure) {
            if ($this->pdo->inTransaction()) {
                $this->pdo->rollBack();
            }
            throw $failure;
        }
    }
}
