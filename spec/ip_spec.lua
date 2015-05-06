
require [[spec.helper]]

describe('', function ()

  local ip

  setup(function ()
    ip = require [[..ip]]
  end)

  teardown(function ()
    ip = nil
  end)

  it('can construct IPv4 from octets', function ()
    assert.not_error(bind(ip.v4, {192, 168, 1, 2}))
  end)

  it('refuses to construct invalid IPv4', function ()
    assert.error(bind(ip.v4, {300, 1, 3, 3}))
    assert.error(bind(ip.v4, {8, 8, 8}))
  end)

  it('converts IPv4 to string correctly', function ()
    assert.equal(tostring(ip.v4({192, 168, 1, 1})), '192.168.1.1')
  end)

  it('returns correct kind for IPv4', function ()
    local addr = ip.v4({1, 2, 3, 4})
    assert.equal(addr:kind(), 'ipv4')
  end)

  it('allows to access IPv4 octets', function ()
    local addr = ip.v4({42, 0, 0, 0})
    assert.equal(addr.octets[1], 42)
  end)

  it('checks IPv4 address format', function ()
    assert.equal(ip.isv4('192.168.007.0xa'), true)
    assert.equal(ip.isv4('1024.0.0.1'),      true)
    assert.equal(ip.isv4('8.0xa.wtf.6'),     false)
  end)

  it('validates IPv4 addresses', function ()
    assert.equal(ip.isv4('192.168.007.0xa', true), true)
    assert.equal(ip.isv4('1024.0.0.1', true),      false)
    assert.equal(ip.isv4('8.0xa.wtf.6', true),     false)
  end)

  it('parses IPv4 in several weird formats', function ()
    assert.same(ip.parsev4('192.168.1.1').octets,  {192, 168, 1, 1})
    assert.same(ip.parsev4('0xc0.168.1.1').octets, {192, 168, 1, 1})
    assert.same(ip.parsev4('192.0250.1.1').octets, {192, 168, 1, 1})
    assert.same(ip.parsev4('0xc0a80101').octets,   {192, 168, 1, 1})
    assert.same(ip.parsev4('030052000401').octets, {192, 168, 1, 1})
    assert.same(ip.parsev4('3232235777').octets,   {192, 168, 1, 1})
  end)

  it('barfs at invalid IPv4', function ()
    assert.error(bind(ip.parsev4, '10.0.0.wtf'))
  end)

  it('matches IPv4 CIDR correctly', function ()
    local addr = ip.v4({10, 5, 0, 1})
    assert.equal(addr == ip.parsev4('0.0.0.0', 0),   true)
    assert.equal(addr == ip.parsev4('11.0.0.0', 8),  false)
    assert.equal(addr == ip.parsev4('10.0.0.0', 8),  true)
    assert.equal(addr == ip.parsev4('10.0.0.1', 8),  true)
    assert.equal(addr == ip.parsev4('10.0.0.10', 8), true)
    assert.equal(addr == ip.parsev4('10.5.5.0', 16), true)
    assert.equal(addr == ip.parsev4('10.4.5.0', 16), false)
    assert.equal(addr == ip.parsev4('10.4.5.0', 15), true)
    assert.equal(addr == ip.parsev4('10.5.0.2', 32), false)
    assert.equal(addr == addr:cidr(32),               true)
  end)

  it('detects reserved IPv4 networks', function ()
    assert.equal(ip.parsev4('0.0.0.0'):range(),         'unspecified')
    assert.equal(ip.parsev4('0.1.0.0'):range(),         'unspecified')
    assert.equal(ip.parsev4('10.1.0.1'):range(),        'private')
    assert.equal(ip.parsev4('192.168.2.1'):range(),     'private')
    assert.equal(ip.parsev4('224.100.0.1'):range(),     'multicast')
    assert.equal(ip.parsev4('169.254.15.0'):range(),    'linkLocal')
    assert.equal(ip.parsev4('127.1.1.1'):range(),       'loopback')
    assert.equal(ip.parsev4('255.255.255.255'):range(), 'broadcast')
    assert.equal(ip.parsev4('240.1.2.3'):range(),       'reserved')
    assert.equal(ip.parsev4('8.8.8.8'):range(),         'unicast')
  end)

  it('can construct IPv6 from parts', function ()
    assert.not_error(bind(
      ip.v6, {0x2001, 0xdb8, 0xf53a, 0, 0, 0, 0, 1}
    ))
  end)

  it('refuses to construct invalid IPv6', function ()
    assert.error(bind(ip.v6, {0xfffff, 0, 0, 0, 0, 0, 0, 1}))
    assert.error(bind(ip.v6, {0xfffff, 0, 0, 0, 0, 0, 1}))
  end)

  it('converts IPv6 to string correctly', function ()
    assert.equal(tostring(ip.v6({0, 0, 0, 0, 0, 0, 0, 1})),               '::1')
    assert.equal(tostring(ip.v6({0x2001, 0xdb8, 0, 0, 0, 0, 0, 0})),      '2001:db8::')
    assert.equal(tostring(ip.v6({0x2001, 0xdb8, 0xf53a, 0, 0, 0, 0, 1})), '2001:db8:f53a::1')
  end)

  it('returns correct kind for IPv6', function ()
    assert.equal(ip.v6({0x2001, 0xdb8, 0xf53a, 0, 0, 0, 0, 1}):kind(), 'ipv6')
  end)

  it('allows to access IPv6 address parts', function ()
    assert.equal(ip.v6({0x2001, 0xdb8, 0xf53a, 0, 0, 42, 0, 1}).parts[6], 42)
  end)

  it('checks IPv6 address format', function ()
    assert.equal(ip.isv6('2001:db8:F53A::1'),     true)
    assert.equal(ip.isv6('200001::1'),            true)
    assert.equal(ip.isv6('::ffff:192.168.1.1'),   true)
    assert.equal(ip.isv6('::ffff:300.168.1.1'),   true)
    assert.equal(ip.isv6('::ffff:300.168.1.1:0'), false)
    assert.equal(ip.isv6('fe80::wtf'),            false)
  end)

  it('validates IPv6 addresses', function ()
    assert.equal(ip.isv6('2001:db8:F53A::1', true),     true)
    assert.equal(ip.isv6('200001::1', true),            false)
    assert.equal(ip.isv6('::ffff:192.168.1.1', true),   true)
    assert.equal(ip.isv6('::ffff:300.168.1.1', true),   false)
    assert.equal(ip.isv6('::ffff:300.168.1.1:0', true), false)
    assert.equal(ip.isv6('2001:db8::F53A::1', true),    false)
    assert.equal(ip.isv6('fe80::wtf', true),            false)
  end)

  it('parses IPv6 in different formats', function ()
    assert.same(ip.parsev6('2001:db8:F53A:0:0:0:0:1').parts, {0x2001, 0xdb8, 0xf53a, 0, 0, 0, 0, 1})
    assert.same(ip.parsev6('fe80::10').parts,                {0xfe80, 0, 0, 0, 0, 0, 0, 0x10})
    assert.same(ip.parsev6('2001:db8:F53A::').parts,         {0x2001, 0xdb8, 0xf53a, 0, 0, 0, 0, 0})
    assert.same(ip.parsev6('::1').parts,                     {0, 0, 0, 0, 0, 0, 0, 1})
    assert.same(ip.parsev6('::').parts,                      {0, 0, 0, 0, 0, 0, 0, 0})
  end)

  it('barfs at invalid IPv6', function ()
    assert.error(bind(ip.parsev6, 'fe80::0::1'))
  end)

  it('matches IPv6 CIDR correctly', function ()
    local addr = ip.parsev6('2001:db8:f53a::1')
    assert.equal(addr == ip.parsev6('::', 0),                  true)
    assert.equal(addr == ip.parsev6('2001:db8:f53a::1:1', 64), true)
    assert.equal(addr == ip.parsev6('2001:db8:f53b::1:1', 48), false)
    assert.equal(addr == ip.parsev6('2001:db8:f531::1:1', 44), true)
    assert.equal(addr == ip.parsev6('2001:db8:f500::1', 40),   true)
    assert.equal(addr == ip.parsev6('2001:db9:f500::1', 40),   false)
    assert.equal(addr == addr:cidr(128),                       true)
  end)

  it('converts between IPv4-mapped IPv6 addresses and IPv4 addresses', function ()
    addr   = ip.parsev4('77.88.21.11')
    mapped = addr:ipv4_mapped_address()
    assert.same(mapped.parts, {0, 0, 0, 0, 0, 0xffff, 0x4d58, 0x150b})
    assert.same(mapped.octets, addr.octets)
  end)

  it('detects reserved IPv6 networks', function ()
    assert.equal(ip.parsev6('::'):range(),                        'unspecified')
    assert.equal(ip.parsev6('fe80::1234:5678:abcd:0123'):range(), 'linkLocal')
    assert.equal(ip.parsev6('ff00::1234'):range(),                'multicast')
    assert.equal(ip.parsev6('::1'):range(),                       'loopback')
    assert.equal(ip.parsev6('fc00::'):range(),                    'uniqueLocal')
    assert.equal(ip.parsev6('::ffff:192.168.1.10'):range(),       'ipv4Mapped')
    assert.equal(ip.parsev6('::ffff:0:192.168.1.10'):range(),     'rfc6145')
    assert.equal(ip.parsev6('64:ff9b::1234'):range(),             'rfc6052')
    assert.equal(ip.parsev6('2002:1f63:45e8::1'):range(),         '6to4')
    assert.equal(ip.parsev6('2001::4242'):range(),                'teredo')
    assert.equal(ip.parsev6('2001:db8::3210'):range(),            'reserved')
    assert.equal(ip.parsev6('2001:470:8:66::1'):range(),          'unicast')
  end)

  it('is able to determine IP address type', function ()
    assert.equal(ip.parse('8.8.8.8'):kind(),          'ipv4')
    assert.equal(ip.parse('2001:db8:3312::1'):kind(), 'ipv6')
  end)

  it('throws an error if tried to parse an invalid address', function ()
    assert.error(bind(ip.parse, '::some.nonsense'))
  end)

  it('correctly parses 1 as an IPv4 address', function ()
    assert.equal(ip.isv6('1'), false)
    assert.equal(ip.isv4('1'), true)
    assert.same(ip.v4({0, 0, 0, 1}), ip.parse('1'))
  end)

  it('does not consider a very large or very small number a valid IP address', function ()
    assert.equal(ip.valid('4999999999'), false)
    assert.equal(ip.valid('-1'),         false)
  end)

end)