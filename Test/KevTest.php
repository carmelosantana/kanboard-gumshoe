<?php

namespace Kanboard\Plugin\Gumshoe\Test;

use Kanboard\Plugin\Gumshoe\Advisory\AdvisoryCache;
use Kanboard\Plugin\Gumshoe\Advisory\Kev;
use Kanboard\Plugin\Gumshoe\Http\Client;
use Kanboard\Plugin\Gumshoe\Http\HttpFailure;
use Kanboard\Plugin\Gumshoe\Http\Response;
use Kanboard\Plugin\Gumshoe\Test\Fakes\FakeTransport;
use KanboardTests\units\Base;

use function Kanboard\Plugin\Gumshoe\Schema\version_1;

require_once __DIR__.'/bootstrap.php';
require_once 'tests/units/Base.php';
require_once __DIR__.'/ReleasesConnection.php';

final class KevTest extends Base
{
    use ReleasesConnection;

    private const OFFICIAL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
    private const MIRROR = 'https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json';

    /** @dataProvider invalidCatalogs */
    public function testAcceptsMirrorAndKeepsLastGoodCatalogOnInvalidRefresh(string $invalid): void
    {
        $pdo = $this->container['db']->getConnection();
        require_once __DIR__.'/../Schema/'.ucfirst(DB_DRIVER).'.php';
        version_1($pdo);
        $valid = file_get_contents(__DIR__.'/fixtures/kev/known_exploited_vulnerabilities.json');
        $firstCve = json_decode($valid, true, flags: JSON_THROW_ON_ERROR)['vulnerabilities'][0]['cveID'];
        $transport = new FakeTransport([
            new Response(503),
            new Response(200, [], $valid),
            new Response(200, [], $invalid),
            new Response(200, [], $invalid),
        ]);
        $client = new Client($transport, 'https://kanboard.example');
        $kev = new Kev($client, new AdvisoryCache($pdo));
        $kev->store($kev->fetch(), 1000);
        self::assertTrue($kev->contains($firstCve));
        $this->expectException(HttpFailure::class);
        try {
            $kev->store($kev->fetch(), 1100);
        } finally {
            self::assertSame([self::OFFICIAL, self::MIRROR, self::OFFICIAL, self::MIRROR], array_column($transport->requests, 'url'));
            self::assertTrue((new Kev($client, new AdvisoryCache($pdo)))->contains($firstCve));
        }
    }

    public static function invalidCatalogs(): iterable
    {
        yield 'missing vulnerabilities' => ['{}'];
        yield 'empty list' => ['{"vulnerabilities":[]}'];
        yield 'not a list' => ['{"vulnerabilities":{"0":{"cveID":"CVE-2021-44228"}}}'];
        yield 'mixed valid and invalid entries' => ['{"vulnerabilities":[{"cveID":"CVE-2021-44228"},{"cveID":"CVE-2021-123"}]}'];
    }
}
