<?php

namespace Kanboard\Plugin\Gumshoe\Run;

use Closure;
use Kanboard\Plugin\Gumshoe\Http\HttpFailure;
use Kanboard\Plugin\Gumshoe\Http\Request;
use Kanboard\Plugin\Gumshoe\Http\Response;
use Kanboard\Plugin\Gumshoe\Http\Transport;

/** The guarded HTTP client may make several transport hops during one method call. */
final class ScanTransport implements Transport
{
    public bool $stopped = false;
    public ?int $retryAt = null;
    public int $completed = 0;
    public ?string $stoppedOperation = null;

    public function __construct(
        private readonly Transport $transport,
        private readonly Closure $clock,
        private readonly ?int $deadline,
        private readonly Closure $keepLease,
    ) {
    }

    public function send(#[\SensitiveParameter] Request $request, #[\SensitiveParameter] array $headers): Response
    {
        $now = ($this->clock)();
        if ($this->deadline !== null && $now >= $this->deadline) {
            $this->stopped = true;
            $this->stoppedOperation = $request->operation;
            throw new HttpFailure($request->operation, null, null, 'deadline_reached');
        }

        if (!($this->keepLease)()) {
            $this->stopped = true;
            throw new LeaseLost();
        }

        $response = $this->transport->send($request, $headers);
        $this->completed++;
        $after = $response->header('retry-after') ?? '';
        if (ctype_digit($after)) {
            $delay = min((int) $after, PHP_INT_MAX - $now);
            $this->retryAt = max($this->retryAt ?? 0, $now + $delay);
        } elseif (preg_match('/\A[A-Z][a-z]{2}, \d{2} [A-Z][a-z]{2} \d{4} \d{2}:\d{2}:\d{2} GMT\z/', $after)) {
            $this->retryAt = max($this->retryAt ?? 0, strtotime($after) ?: $now);
        }
        return $response;
    }
}
