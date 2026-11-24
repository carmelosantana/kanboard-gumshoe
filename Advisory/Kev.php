<?php

namespace Kanboard\Plugin\Gumshoe\Advisory;

use Kanboard\Plugin\Gumshoe\Http\Client;
use Kanboard\Plugin\Gumshoe\Http\HttpFailure;
use Kanboard\Plugin\Gumshoe\Http\Request;

final class Kev
{
    private const OFFICIAL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
    private const MIRROR = 'https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json';
    private const CATALOG = 'catalog';

    /** @var array<string, true>|null */
    private ?array $entries = null;

    public function __construct(private readonly Client $client, private readonly AdvisoryCache $cache)
    {
    }

    public function refresh(): void
    {
        foreach ([self::OFFICIAL, self::MIRROR] as $url) {
            try {
                $entries = $this->download($url);
            } catch (HttpFailure $failure) {
                continue;
            }
            $this->cache->put('kev', self::CATALOG, $entries, null, time());
            $this->entries = $entries;
            return;
        }
        throw $failure;
    }

    public function contains(string $cve): bool
    {
        $this->entries ??= $this->cache->get('kev', self::CATALOG)['body'] ?? [];
        return isset($this->entries[$cve]);
    }

    /** @return array<string, true> */
    private function download(string $url): array
    {
        $host = parse_url($url, PHP_URL_HOST);
        $response = $this->client->send(new Request('kev', $url));
        if ($response->status !== 200) {
            throw new HttpFailure('kev', $host, $response->status, 'request_failed');
        }
        $catalog = json_decode($response->body);
        if (!is_array($catalog->vulnerabilities ?? null) || $catalog->vulnerabilities === []) {
            throw new HttpFailure('kev', $host, 200, 'invalid_response');
        }
        $entries = [];
        foreach ($catalog->vulnerabilities as $entry) {
            $cve = $entry->cveID ?? null;
            if (!is_string($cve) || preg_match('/\ACVE-[0-9]{4}-[0-9]{4,}\z/', $cve) !== 1) {
                throw new HttpFailure('kev', $host, 200, 'invalid_response');
            }
            $entries[$cve] = true;
        }
        return $entries;
    }
}
