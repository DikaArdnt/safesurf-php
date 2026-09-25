<?php

declare(strict_types=1);

namespace SafeSurf\Tests;

use PHPUnit\Framework\TestCase;
use SafeSurf\Util\DnsQuery;

final class DnsQueryTest extends TestCase
{
    public function testBuildQueryStructure(): void
    {
        $q = DnsQuery::buildQuery('Example.COM');
        $this->assertNotNull($q);

        // Header: id(2) flags(2, RD set) qdcount=1, an/ns/ar=0
        $this->assertSame(12 + 13 + 4, strlen($q));
        $this->assertSame("\x01\x00", substr($q, 2, 2)); // RD flag
        $this->assertSame("\x00\x01\x00\x00\x00\x00\x00\x00", substr($q, 4, 8));
        // QNAME: len('example')=7 + 'example' + len('com')=3 + 'com' + 0x00
        $this->assertSame("\x07example\x03com\x00", substr($q, 12, 13));
        // QTYPE=A, QCLASS=IN
        $this->assertSame("\x00\x01\x00\x01", substr($q, 25, 4));
    }

    public function testBuildQueryRejectsInvalidNames(): void
    {
        $this->assertNull(DnsQuery::buildQuery(''));
        $this->assertNull(DnsQuery::buildQuery('exa mple.com')); // space inside label
        $this->assertNull(DnsQuery::buildQuery(str_repeat('a', 64) . '.com')); // label > 63
        $this->assertNull(DnsQuery::buildQuery('bad_label!.com'));
    }

    /** Craft a synthetic DNS response: question example.com, one A answer 180.131.144.144. */
    private function syntheticResponse(string $queryId): string
    {
        $question = "\x07example\x03com\x00\x00\x01\x00\x01";
        $answer = "\xc0\x0c" // name pointer to question
            . "\x00\x01"     // type A
            . "\x00\x01"     // class IN
            . "\x00\x00\x01\x2c" // ttl 300
            . "\x00\x04"     // rdlength 4
            . pack('C4', 180, 131, 144, 144);

        return $queryId
            . "\x81\x80"                     // flags: QR + RD + RA, rcode 0
            . "\x00\x01\x00\x01\x00\x00\x00\x00" // qd=1, an=1
            . $question . $answer;
    }

    public function testParseResponseExtractsARecord(): void
    {
        $query = DnsQuery::buildQuery('example.com');
        $this->assertNotNull($query);

        $out = DnsQuery::parseResponse($this->syntheticResponse(substr($query, 0, 2)), substr($query, 0, 2));
        $this->assertNotNull($out);
        $this->assertSame('ok', $out['status']);
        $this->assertSame(['180.131.144.144'], $out['ips']);
    }

    public function testParseResponseRejectsMismatchedId(): void
    {
        $query = DnsQuery::buildQuery('example.com');
        $this->assertNotNull($query);
        $this->assertNull(DnsQuery::parseResponse($this->syntheticResponse("\xAA\xBB"), substr($query, 0, 2)));
    }

    public function testParseResponseNxdomain(): void
    {
        $queryId = "\x12\x34";
        $raw = $queryId
            . "\x81\x83" // QR + RD + RA, rcode 3 (NXDOMAIN)
            . "\x00\x01\x00\x00\x00\x00\x00\x00"
            . "\x07example\x03com\x00\x00\x01\x00\x01";

        $out = DnsQuery::parseResponse($raw, $queryId);
        $this->assertNotNull($out);
        $this->assertSame('nxdomain', $out['status']);
        $this->assertSame([], $out['ips']);
    }

    public function testParseResponseTruncatedAndNonResponse(): void
    {
        $queryId = "\x12\x34";
        $this->assertNull(DnsQuery::parseResponse("\x12\x34\x81\x80", $queryId));
        // QR bit unset → not a response
        $this->assertNull(DnsQuery::parseResponse($queryId . "\x01\x00" . str_repeat("\x00", 8), $queryId));
    }

    public function testQueryRejectsPrivateAndInvalidResolver(): void
    {
        $this->assertNull(DnsQuery::query('not-an-ip', 'example.com', 1000));
        $this->assertNull(DnsQuery::query('127.0.0.1', 'example.com', 100));
    }
}
