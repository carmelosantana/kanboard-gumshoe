<?php

namespace Kanboard\Plugin\Gumshoe\GitHub;

use DateTimeImmutable;
use Kanboard\Plugin\Gumshoe\Http\Client;
use Kanboard\Plugin\Gumshoe\Http\HttpFailure;
use Kanboard\Plugin\Gumshoe\Http\Request;
use stdClass;

final class RepoLister
{
    public function __construct(private readonly Client $client)
    {
    }

    /** @return array{owner: string, status: 'complete'|'incomplete', repos: list<array>, retryAt: ?int} */
    public function list(array $owner, ?string $jobRef = null): array
    {
        $login = strtolower($owner['login']);
        $incomplete = ['owner' => $login, 'status' => 'incomplete', 'repos' => [], 'retryAt' => null];
        if (!preg_match('/\A[a-z0-9](?:[a-z0-9-]{0,38})\z/', $login) || !in_array($owner['kind'], ['user', 'org'], true)) {
            return $incomplete;
        }

        $isUser = $owner['kind'] === 'user';
        $path = $isUser ? '/user/repos?affiliation=owner' : '/orgs/'.$login.'/repos?type=all';
        $request = new Request('gh.list', 'https://api.github.com'.$path, $login);
        $repos = [];
        $names = [];
        $visited = [];
        try {
            do {
                if (isset($visited[$request->url])) {
                    return $incomplete;
                }
                $visited[$request->url] = true;
                $response = $this->client->send($request, $jobRef);
                $incomplete['retryAt'] = $response->retryAt;
                $items = $response->status === 200 ? json_decode($response->body) : null;
                if (!is_array($items)) {
                    return $incomplete;
                }

                foreach ($items as $item) {
                    $repoOwner = $item->owner->login ?? null;
                    if (!is_string($repoOwner)) {
                        return $incomplete;
                    }
                    if (strcasecmp($repoOwner, $login) !== 0) {
                        if ($isUser) {
                            continue;
                        }
                        return $incomplete;
                    }
                    $repo = $this->repository($item);
                    if ($repo === null || isset($repos[$repo['github_id']]) || isset($names[strtolower($repo['name'])])) {
                        return $incomplete;
                    }
                    $repos[$repo['github_id']] = $repo;
                    $names[strtolower($repo['name'])] = true;
                }

                $request = $this->client->nextPage($request, $response);
                if ($request !== null && $response->retryAt !== null) {
                    return $incomplete;
                }
            } while ($request !== null);
        } catch (HttpFailure) {
            return $incomplete;
        }

        return ['owner' => $login, 'status' => 'complete', 'repos' => array_values($repos), 'retryAt' => $response->retryAt];
    }

    private function repository(#[\SensitiveParameter] stdClass $item): ?array
    {
        if (!is_int($item->id ?? null) || $item->id <= 0
            || !is_string($item->name ?? null) || !preg_match('/\A[a-zA-Z0-9_.-]{1,100}\z/', $item->name)
            || in_array($item->name, ['.', '..'], true)
            || !is_bool($item->private ?? null) || !is_bool($item->fork ?? null) || !is_bool($item->archived ?? null)
            || !is_string($item->default_branch ?? null) || $item->default_branch === ''
            || !property_exists($item, 'pushed_at')) {
            return null;
        }

        $pushedAt = null;
        if ($item->pushed_at !== null) {
            if (!is_string($item->pushed_at)
                || !preg_match('/\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\z/', $item->pushed_at)) {
                return null;
            }
            $format = 'Y-m-d\TH:i:s\Z';
            $date = DateTimeImmutable::createFromFormat($format, $item->pushed_at, new \DateTimeZone('UTC'));
            if ($date === false || $date->format($format) !== $item->pushed_at) {
                return null;
            }
            $pushedAt = $date->getTimestamp();
        }

        return [
            'github_id' => $item->id, 'name' => $item->name, 'private' => $item->private, 'fork' => $item->fork,
            'archived' => $item->archived, 'pushed_at' => $pushedAt, 'default_branch' => $item->default_branch,
        ];
    }
}
