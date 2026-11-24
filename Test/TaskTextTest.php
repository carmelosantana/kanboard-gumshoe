<?php

namespace Kanboard\Plugin\Gumshoe\Test;

use Dom\HTMLDocument;
use Dom\XPath;
use Kanboard\Controller\TaskViewController;
use Kanboard\Core\Http\Request;
use Kanboard\Core\Http\Response;
use Kanboard\Core\Markdown;
use Kanboard\Helper\TextHelper;
use Kanboard\Plugin\Gumshoe\Finding\TaskText;
use KanboardTests\units\Base;

require_once 'tests/units/Base.php';
require_once __DIR__.'/ReleasesConnection.php';

final class TaskTextTest extends Base
{
    use ReleasesConnection;

    public static function htmlModes(): array
    {
        return [[true], [false]];
    }

    /** @dataProvider htmlModes */
    public function testTaskPageRendersOnlyPluginMarkdown(bool $escapeHtml): void
    {
        $hostile = '</script><img src=x>';
        $summary = $hostile.' **summary** ![image](https://example.org/x) https://example.org/x @admin ~~literal~~ '
            .'ghp_'.str_repeat('a', 24);
        $description = TaskText::description($summary, [
            'CVE-2018-16492', 'GHSA-mh6f-8j2x-4483', 'MAL-2025-20690', 'https://example.org/x',
        ], [
            ['repo' => 'symfony/yaml', 'path' => 'z/package-lock.json', 'version' => '0.1.1', 'scope' => 'prod'],
            ['repo' => 'symfony/yaml', 'path' => 'a`|b/'.$hostile, 'version' => '0.1.1', 'scope' => 'dev'],
        ]);
        self::assertStringNotContainsString('@admin', $description);
        $project = $this->container['projectModel']->create(['name' => 'Findings']);
        $task = $this->container['taskCreationModel']->create([
            'project_id' => $project, 'title' => 'Finding', 'description' => $description,
        ]);
        $this->container['request'] = new Request($this->container, ['HTTP_X_REQUESTED_WITH' => 'XMLHttpRequest'], ['task_id' => $task]);
        $response = $this->createMock(Response::class);
        $response->expects(self::once())->method('html')->willReturnCallback(static function ($html) use ($hostile): void {
            $document = HTMLDocument::createFromString($html, LIBXML_NOERROR | \Dom\HTML_NO_DEFAULT_NS, 'UTF-8');
            $xpath = new XPath($document);
            $table = $xpath->query('//table[thead/tr/th[1]="Repository"]')->item(0);
            self::assertNotNull($table);
            self::assertSame('a`|b/'.$hostile, $xpath->evaluate('string(tbody/tr[1]/td[2])', $table));
            self::assertSame('z/package-lock.json', $xpath->evaluate('string(tbody/tr[2]/td[2])', $table));
            self::assertStringContainsString($hostile.' **summary** ![image](https://example.org/x)', $document->documentElement->textContent);
            self::assertStringContainsString('[redacted]', $document->documentElement->textContent);
            self::assertStringNotContainsString('<img src=x>', $html);
            self::assertSame(0, $xpath->query('//img[@src="x" or @src="https://example.org/x"] | //a[@href="https://example.org/x"]')->length);
            foreach ([
                'https://nvd.nist.gov/vuln/detail/CVE-2018-16492',
                'https://github.com/advisories/GHSA-mh6f-8j2x-4483',
                'https://osv.dev/vulnerability/MAL-2025-20690',
            ] as $url) {
                self::assertSame(1, $xpath->query('//a[@href="'.$url.'"]')->length);
            }
        });
        $this->container['response'] = $response;
        // Core reads a process constant. Supply the other mode to the same parser
        // when rendering both settings within this test process.
        if ($escapeHtml !== MARKDOWN_ESCAPE_HTML) {
            $textHelper = new class($this->container) extends TextHelper {
                public function markdown($text, $isPublicLink = false)
                {
                    return (new Markdown($this->container, $isPublicLink))
                        ->setMarkupEscaped(!MARKDOWN_ESCAPE_HTML)->setBreaksEnabled(true)->text($text ?: '');
                }
            };
            $this->container['helper']->register('text', $textHelper::class);
        }

        (new TaskViewController($this->container))->show();
    }

    public function testSummaryIsCappedAtTwoThousandCharacters(): void
    {
        $summary = str_repeat('é', 2000).'discarded';
        self::assertSame(str_repeat('é', 2000), TaskText::description($summary, [], []));
    }
}
