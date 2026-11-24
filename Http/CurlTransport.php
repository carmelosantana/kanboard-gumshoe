<?php

namespace Kanboard\Plugin\Gumshoe\Http;

final class CurlTransport implements Transport
{
    public const WIRE_LIMIT = 14 * 1024 * 1024;
    public const DECODED_LIMIT = 10 * 1024 * 1024;

    private readonly \Closure $curl;
    private mixed $handle = null;

    public function __construct(#[\SensitiveParameter] private readonly ?string $proxy = null, ?callable $adapter = null)
    {
        $this->curl = $adapter === null
            ? static fn (string $function, #[\SensitiveParameter] mixed ...$args) => $function(...$args)
            : \Closure::fromCallable($adapter);
    }

    public function send(#[\SensitiveParameter] Request $request, #[\SensitiveParameter] array $headers): Response
    {
        $curl = $this->curl;
        $received = [];
        $body = '';
        $reason = null;
        $status = null;
        $proxy = $this->proxy ?? '';
        $options = [
            CURLOPT_URL => $request->url,
            CURLOPT_CUSTOMREQUEST => $request->method,
            CURLOPT_HTTPHEADER => [],
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_TIMEOUT => 20,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_PROXY => $proxy,
            CURLOPT_NOPROXY => $proxy === '' ? '*' : '',
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_ENCODING => '',
            CURLOPT_NOPROGRESS => false,
            CURLOPT_XFERINFOFUNCTION => static function ($handle, $downloadTotal, $downloadNow) use (&$reason): int {
                if ($downloadTotal > self::WIRE_LIMIT || $downloadNow > self::WIRE_LIMIT) {
                    $reason = 'wire_too_large';
                    return 1;
                }
                return 0;
            },
            CURLOPT_WRITEFUNCTION => static function ($handle, #[\SensitiveParameter] string $chunk) use (&$body, &$reason): int {
                $length = strlen($chunk);
                if (strlen($body) + $length > self::DECODED_LIMIT) {
                    $reason = 'decoded_too_large';
                    return 0;
                }
                $body .= $chunk;
                return $length;
            },
            CURLOPT_HEADERFUNCTION => static function ($handle, #[\SensitiveParameter] string $line) use (&$received): int {
                if (str_starts_with($line, 'HTTP/')) {
                    $received = [];
                } elseif (($colon = strpos($line, ':')) !== false) {
                    $name = strtolower(substr($line, 0, $colon));
                    $value = trim(substr($line, $colon + 1));
                    $received[$name] = isset($received[$name]) ? $received[$name].', '.$value : $value;
                }
                return strlen($line);
            },
        ];
        foreach ($headers as $name => $value) {
            $options[CURLOPT_HTTPHEADER][] = $name.': '.$value;
        }
        if ($request->body !== null) {
            $options[CURLOPT_POSTFIELDS] = $request->body;
        }

        try {
            $this->handle ??= $curl('curl_init') ?: null;
            if ($this->handle !== null && $curl('curl_setopt_array', $this->handle, $options)) {
                $result = $curl('curl_exec', $this->handle);
                $status = $curl('curl_getinfo', $this->handle, CURLINFO_RESPONSE_CODE) ?: null;
                if ($curl('curl_getinfo', $this->handle, CURLINFO_SIZE_DOWNLOAD_T) > self::WIRE_LIMIT) {
                    $reason = 'wire_too_large';
                }
                if ($result !== false && $status !== null && $reason === null) {
                    return new Response($status, $received, $body);
                }
            }
        } catch (\Throwable) {
            // Adapter errors can contain options or response data.
        } finally {
            // Best effort on our copies, alongside resetting libcurl's options.
            foreach ($options[CURLOPT_HTTPHEADER] as &$line) {
                sodium_memzero($line);
            }
            unset($line, $options[CURLOPT_HTTPHEADER]);
            if ($this->handle !== null) {
                try {
                    $curl('curl_reset', $this->handle);
                } catch (\Throwable) {
                    $this->handle = null;
                    throw new HttpFailure($request->operation, parse_url($request->url, PHP_URL_HOST), $status, 'transport_error');
                }
            }
        }
        throw new HttpFailure($request->operation, parse_url($request->url, PHP_URL_HOST), $status, $reason ?? 'transport_error');
    }
}
