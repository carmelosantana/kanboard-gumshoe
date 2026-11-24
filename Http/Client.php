<?php

namespace Kanboard\Plugin\Gumshoe\Http;

use Kanboard\Plugin\Gumshoe\Plugin;
use Kanboard\Plugin\Gumshoe\Secrets\TokenSource;
use Pimple\Container;

final class Client
{
    private const GITHUB = 'api.github.com';
    private const OPERATIONS = ['gh.list', 'gh.repo', 'gh.branch', 'gh.tree', 'gh.blob', 'gh.advisories', 'kev'];
    private const REQUEST_HEADERS = [
        'accept' => 'Accept',
        'content-type' => 'Content-Type',
        'if-none-match' => 'If-None-Match',
        'if-modified-since' => 'If-Modified-Since',
        'x-github-api-version' => 'X-GitHub-Api-Version',
    ];
    private const REDIRECTS = [301, 302, 303, 307, 308];
    private const LIST_QUERY_KEYS = ['page', 'per_page', 'type', 'affiliation', 'sort', 'direction', 'before', 'after', 'since', 'cursor'];
    private const NUMERIC_LIST_PATH = '~\A/(?:organizations|user)/[0-9]+/repos\z~i';

    private array $secondaryLimits = [];
    /** @var \WeakMap<Request, string|false> Validated next pages and their first-page numeric endpoint, if known. */
    private readonly \WeakMap $listPages;
    private readonly \Closure $clock;
    private readonly string $userAgent;

    public function __construct(
        private readonly Transport $transport,
        string $applicationUrl,
        private readonly ?TokenSource $tokens = null,
        ?\Closure $clock = null,
    ) {
        $this->clock = $clock ?? time(...);
        $this->listPages = new \WeakMap();
        $version = (new Plugin(new Container()))->getPluginVersion();
        $this->userAgent = 'Kanboard-Gumshoe/'.$version.' (+'.$applicationUrl.')';
    }

    public function send(#[\SensitiveParameter] Request $request, ?string $jobRef = null): Response
    {
        $operation = $this->operation($request);
        [$url, $host, $path] = $this->target($operation, $request->url);
        $owner = $this->validateRequest($request, $host, $path);
        $baseHeaders = ['User-Agent' => $this->userAgent];
        $headers = $baseHeaders;
        foreach ($request->headers as $name => $value) {
            $canonical = self::REQUEST_HEADERS[strtolower((string) $name)] ?? null;
            if ($canonical === null || !is_string($value) || preg_match('/[\x00-\x1f\x7f]/', $value) !== 0) {
                throw new HttpFailure($operation, $host, null, 'header_not_allowed');
            }
            $headers[$canonical] = $value;
        }

        $secret = null;
        $now = ($this->clock)();
        try {
            if ($owner !== null) {
                try {
                    $secret = $this->tokens?->forOwner($owner, $jobRef)?->reveal();
                } catch (\Throwable) {
                    throw new HttpFailure($operation, $host, null, 'token_unavailable');
                }
                if ($secret === null || preg_match('/\A[A-Za-z0-9_]+\z/', $secret) !== 1) {
                    throw new HttpFailure($operation, $host, null, 'token_unavailable');
                }
                $headers['Authorization'] = 'Bearer '.$secret;
            }

            try {
                $response = $this->hop($request->withUrl($url), $host, $headers, $secret);
            } finally {
                // Best effort on our copy. PHP or the transport may have made other copies.
                if (isset($headers['Authorization'])) {
                    sodium_memzero($headers['Authorization']);
                }
                unset($headers);
            }
            if ($owner !== null) {
                $this->tokens->observeGithub($owner, $response, $now);
            }
            if (in_array($response->status, self::REDIRECTS, true)) {
                $location = $response->header('location');
                if ($operation !== 'gh.blob' || $location === null || str_contains($location, '[redacted]')) {
                    throw new HttpFailure($operation, $host, $response->status, 'redirect_not_allowed');
                }
                [$url, $host] = $this->target($operation, $location, redirect: true);
                $response = $this->hop(new Request($operation, $url), $host, $baseHeaders, $secret);
                if (in_array($response->status, self::REDIRECTS, true)) {
                    throw new HttpFailure($operation, $host, $response->status, 'redirect_not_allowed');
                }
            }

            $retryAt = $this->retryAt($response, $host, $owner, $now);
            return new Response($response->status, $response->headers, $response->body, $retryAt);
        } finally {
            if ($secret !== null) {
                sodium_memzero($secret);
            }
        }
    }

    /** Validate the next Link target against the endpoint serving the current page. */
    public function nextPage(#[\SensitiveParameter] Request $request, #[\SensitiveParameter] Response $response): ?Request
    {
        $link = $response->header('link') ?? '';
        preg_match_all('/<([^>]*)>((?:[ \t]*;[ \t]*[\w-]+(?:[ \t]*=[ \t]*(?:"[^"]*"|[^,;\s]+))?)*)/', $link, $entries, PREG_SET_ORDER);
        $next = null;
        foreach ($entries as [, $url, $parameters]) {
            if (preg_match('/;[ \t]*rel[ \t]*=[ \t]*(?:"([^"]*)"|([^;\s]+))/i', $parameters, $relation)
                && in_array('next', preg_split('/\s+/', ($relation[1] ?: $relation[2])), true)) {
                $operation = $this->operation($request);
                [$currentUrl, $host, $path] = $this->target($operation, $request->url);
                [$url, $nextHost, $nextPath] = $this->target($operation, $url);
                if ($next !== null || $host !== $nextHost) {
                    throw new HttpFailure($operation, $host, $response->status, 'pagination_not_allowed');
                }
                $next = $request->withUrl($url);
                if ($operation === 'gh.list') {
                    $owner = $this->validateRequest($request, $host, $path);
                    $numericPath = $this->listPages[$request]
                        ?? $this->numericListPath($path, parse_url($currentUrl, PHP_URL_QUERY) ?? '', $owner, $response);
                    if (($nextPath !== $path && $nextPath !== $numericPath)
                        || !$this->validListQuery(parse_url($url, PHP_URL_QUERY) ?? '')) {
                        throw new HttpFailure($operation, $host, $response->status, 'pagination_not_allowed');
                    }
                    $this->listPages[$next] = $numericPath;
                } elseif ($path !== $nextPath && !str_starts_with($nextPath, rtrim($path, '/').'/')) {
                    throw new HttpFailure($operation, $host, $response->status, 'pagination_not_allowed');
                }
                $this->validateRequest($next, $nextHost, $nextPath);
            }
        }
        return $next;
    }

    private function numericListPath(
        #[\SensitiveParameter] string $path,
        #[\SensitiveParameter] string $query,
        ?string $owner,
        #[\SensitiveParameter] Response $response,
    ): string|false {
        if ($owner === null || $response->status !== 200 || !$this->validListQuery($query)) {
            return false;
        }
        parse_str($query, $parameters);
        if (($parameters['page'] ?? '1') !== '1'
            || array_intersect_key($parameters, array_flip(['before', 'after', 'since', 'cursor']))) {
            return false;
        }
        $items = json_decode($response->body, true);
        if (!is_array($items) || !array_is_list($items)) {
            return false;
        }
        $id = null;
        foreach ($items as $item) {
            $login = $item['owner']['login'] ?? null;
            if (!is_string($login) || strcasecmp($login, $owner) !== 0) {
                continue;
            }
            $itemId = $item['owner']['id'] ?? null;
            if (!is_int($itemId) || $itemId <= 0 || ($id !== null && $itemId !== $id)) {
                return false;
            }
            $id = $itemId;
        }
        if ($id === null) {
            return false;
        }
        $prefix = str_starts_with(strtolower($path), '/orgs/') ? '/organizations/' : '/user/';
        return $prefix.$id.'/repos';
    }

    private function validListQuery(#[\SensitiveParameter] string $query): bool
    {
        if ($query === '') {
            return true;
        }
        if (str_contains($query, ';')) {
            return false;
        }
        $seen = [];
        foreach (explode('&', $query) as $parameter) {
            [$key, $value] = array_pad(explode('=', $parameter, 2), 2, null);
            if ($value === null || isset($seen[$key]) || !in_array($key, self::LIST_QUERY_KEYS, true)) {
                return false;
            }
            $seen[$key] = true;
        }
        return true;
    }

    private function operation(#[\SensitiveParameter] Request $request): string
    {
        if (in_array($request->operation, self::OPERATIONS, true)
            || preg_match('/\Aosv\.[a-z][a-z0-9_-]{0,31}\z/', $request->operation) === 1) {
            return $request->operation;
        }
        throw new HttpFailure('unknown', null, null, 'operation_not_allowed');
    }

    /** @return array{string, string, string} Canonical URL, host and path. */
    private function target(string $operation, #[\SensitiveParameter] string $url, bool $redirect = false): array
    {
        $parts = parse_url($url);
        $host = strtolower($parts['host'] ?? '');
        $path = $parts['path'] ?? '/';
        $allowedHost = $redirect
            ? preg_match('/\A(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+githubusercontent\.com\z/', $host) === 1
            : in_array($host, [self::GITHUB, 'api.osv.dev', 'www.cisa.gov', 'raw.githubusercontent.com'], true);

        // Rebuild the authority from the parsed components. Reject ambiguous path segments before libcurl sees them.
        $decoded = rawurldecode($path);
        if (!$allowedHost || strtolower($parts['scheme'] ?? '') !== 'https'
            || ($parts['port'] ?? 443) !== 443 || isset($parts['user']) || isset($parts['pass']) || isset($parts['fragment'])
            || str_contains($url, '\\') || preg_match('/[\x00-\x20\x7f]/', $url) !== 0
            || str_contains($decoded, '\\') || preg_match('~[\x00-\x1f\x7f]|(?:^|/)\.{1,2}(?:/|$)|%[0-9a-f]{2}~i', $decoded) !== 0) {
            throw new HttpFailure($operation, null, null, 'host_not_allowed');
        }

        $query = isset($parts['query']) ? '?'.$parts['query'] : '';
        return ['https://'.$host.$path.$query, $host, $path];
    }

    /** Return the owner of an authenticated request. */
    private function validateRequest(#[\SensitiveParameter] Request $request, string $host, #[\SensitiveParameter] string $path): ?string
    {
        $operation = $request->operation;
        $github = str_starts_with($operation, 'gh.');
        $allowedHost = match (true) {
            $github => $host === self::GITHUB,
            $operation === 'kev' => in_array($host, ['www.cisa.gov', 'raw.githubusercontent.com'], true),
            default => $host === 'api.osv.dev',
        };
        if (!$allowedHost) {
            throw new HttpFailure($operation, $host, null, 'host_not_allowed');
        }
        if (!(($request->method === 'GET' && $request->body === null)
            || (!$github && $operation !== 'kev' && $request->method === 'POST'))) {
            throw new HttpFailure($operation, $host, null, 'method_not_allowed');
        }
        if ($operation === 'gh.list' && preg_match(self::NUMERIC_LIST_PATH, $path) === 1) {
            if ($request->owner === null || ($this->listPages[$request] ?? false) !== $path) {
                throw new HttpFailure($operation, $host, null, 'owner_not_allowed');
            }
            return strtolower($request->owner);
        }
        if (!$github || $request->owner === null) {
            return null;
        }

        $owner = strtolower($request->owner);
        if (preg_match('/\A[a-z0-9](?:[a-z0-9-]{0,38})\z/', $owner) !== 1) {
            throw new HttpFailure($operation, $host, null, 'owner_not_allowed');
        }
        $repo = '/repos/'.$owner.'/[a-z0-9_.-]+';
        $endpoint = match ($operation) {
            'gh.list' => '/(?:user/repos|(?:users|orgs)/'.$owner.'/repos)',
            'gh.repo' => $repo,
            'gh.branch' => $repo.'/branches/.+',
            'gh.tree' => $repo.'/git/trees/[a-z0-9]+',
            'gh.blob' => $repo.'/git/blobs/[a-z0-9]+',
            'gh.advisories' => '/advisories',
        };
        if (preg_match('~\A'.$endpoint.'\z~i', $path) !== 1) {
            throw new HttpFailure($operation, $host, null, 'owner_not_allowed');
        }
        return $owner;
    }

    private function hop(
        #[\SensitiveParameter] Request $request,
        string $host,
        #[\SensitiveParameter] array $headers,
        #[\SensitiveParameter] ?string $secret,
    ): Response {
        try {
            $response = $this->transport->send($request, $headers);
        } catch (HttpFailure $failure) {
            $reason = in_array($failure->reason, ['wire_too_large', 'decoded_too_large'], true) ? $failure->reason : 'transport_error';
            throw new HttpFailure($request->operation, $host, $failure->status, $reason);
        } catch (\Throwable) {
            throw new HttpFailure($request->operation, $host, null, 'transport_error');
        }

        if ($secret === null) {
            return $response;
        }
        $clean = [];
        foreach ($response->headers as $name => $value) {
            $clean[str_replace($secret, '[redacted]', $name)] = str_replace($secret, '[redacted]', $value);
        }
        return new Response($response->status, $clean, str_replace($secret, '[redacted]', $response->body));
    }

    private function retryAt(#[\SensitiveParameter] Response $response, string $host, ?string $owner, int $now): ?int
    {
        $key = $owner ?? '';
        $github = $host === self::GITHUB;
        if ($github && $response->status < 400) {
            unset($this->secondaryLimits[$key]);
        }
        $retryAfter = $response->header('retry-after') ?? '';
        if (ctype_digit($retryAfter)) {
            return $now + min(PHP_INT_MAX - $now, (int) $retryAfter);
        }
        if (preg_match('/\A[A-Z][a-z]{2}, \d{2} [A-Z][a-z]{2} \d{4} \d{2}:\d{2}:\d{2} GMT\z/', $retryAfter)) {
            $date = strtotime($retryAfter);
            if ($date !== false) {
                return max($now, $date);
            }
        }
        $reset = $response->header('x-ratelimit-reset') ?? '';
        if ($github && $response->header('x-ratelimit-remaining') === '0' && ctype_digit($reset)) {
            return max($now, (int) $reset);
        }
        if ($github && ($response->status === 429
            || ($response->status === 403 && stripos($response->body, 'secondary rate limit') !== false))) {
            $repeats = $this->secondaryLimits[$key] = min(4, ($this->secondaryLimits[$key] ?? -1) + 1);
            return $now + min(900, 60 * (2 ** $repeats));
        }
        return null;
    }
}
