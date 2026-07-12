<?php
if (!defined('ABSPATH')) exit;

/**
 * PN_Mailguard_Whois
 *
 * Performs a WHOIS lookup for an IPv4/IPv6 address using the RDAP REST API
 * (rdap.org) via HTTPS. This avoids the need for direct TCP connections on
 * port 43, which are often blocked on shared hosting.
 *
 * Usage:
 *   $result = PN_Mailguard_Whois::lookup('1.2.3.4');
 *
 * Returns array:
 *   [
 *     'status'       => 'success',   // or 'error'
 *     'ip'           => '1.2.3.4',
 *     'inetnum'      => '1.0.0.0 - 1.255.255.255',
 *     'netname'      => 'APNIC-LABS',
 *     'org'          => 'APNIC Research',
 *     'country'      => 'AU',
 *     'person'       => 'John Doe',
 *     'email'        => '',
 *     'remarks'      => '',
 *     'source'       => 'APNIC',
 *     'error'        => '',
 *   ]
 */
class PN_Mailguard_Whois {

    /**
     * Perform WHOIS lookup for the given IP address using RDAP HTTPS API.
     *
     * @param string $ip
     * @return array
     */
    public static function lookup(string $ip): array {
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return [
                'status' => 'error',
                'error'  => sprintf(__('Invalid IPv4 address: %s', 'pointnet-mailguard'), $ip),
            ];
        }

        // Use rdap.org REST API — no API key required
        $url = 'https://rdap.org/ip/' . urlencode($ip);

        $response = wp_remote_get($url, [
            'timeout' => 15,
            'headers' => [
                'Accept'     => 'application/json',
                'User-Agent' => 'PointNet-MailGuard/1.0',
            ],
        ]);

        if (is_wp_error($response)) {
            return [
                'status' => 'error',
                'error'  => sprintf(
                    __('WHOIS lookup failed: %s', 'pointnet-mailguard'),
                    $response->get_error_message()
                ),
            ];
        }

        $code = wp_remote_retrieve_response_code($response);
        if ($code !== 200) {
            return [
                'status' => 'error',
                'error'  => sprintf(
                    __('WHOIS lookup returned HTTP %d', 'pointnet-mailguard'),
                    $code
                ),
            ];
        }

        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);

        if (!is_array($data) || empty($data['handle'])) {
            return [
                'status' => 'error',
                'error'  => __('Invalid response from WHOIS service.', 'pointnet-mailguard'),
            ];
        }

        // Parse RDAP JSON response into our expected fields
        return self::parse_rdap_response($ip, $data);
    }

    /**
     * Parse RDAP JSON response and extract common WHOIS fields.
     *
     * @param string $ip
     * @param array  $data  RDAP JSON decoded array
     * @return array
     */
    private static function parse_rdap_response(string $ip, array $data): array {
        $fields = [
            'status'  => 'success',
            'ip'      => $ip,
            'inetnum' => '',
            'netname' => '',
            'org'     => '',
            'country' => '',
            'person'  => '',
            'email'   => '',
            'remarks' => '',
            'source'  => '',
            'error'   => '',
        ];

        // Port Control (inetnum) from startAddress - endAddress
        $start = $data['startAddress'] ?? '';
        $end   = $data['endAddress'] ?? '';
        if (!empty($start) && !empty($end)) {
            $fields['inetnum'] = $start . ' - ' . $end;
        }

        // Net name from name
        if (!empty($data['name'])) {
            $fields['netname'] = $data['name'];
        }

        // Source/registry from port43 or top-level LDAP name
        if (!empty($data['port43'])) {
            $fields['source'] = $data['port43'];
        } elseif (!empty($data['rdapConventions'])) {
            $fields['source'] = $data['rdapConventions'][0] ?? '';
        }

        // Extract entities (organizations, persons, contacts)
        if (!empty($data['entities'])) {
            foreach ($data['entities'] as $entity) {
                $entity_roles = $entity['roles'] ?? [];
                $is_org      = in_array('registration', $entity_roles, true) || in_array('administrative', $entity_roles, true);
                $is_tech     = in_array('technical', $entity_roles, true);
                $is_abuse    = in_array('abuse', $entity_roles, true);
                $is_billing  = in_array('billing', $entity_roles, true);

                // If this entity has a "handle" and looks like org info, capture org & country
                if (!empty($entity['vcardArray'])) {
                    $vcard = self::parse_vcard($entity['vcardArray']);
                } else {
                    $vcard = [];
                }

                // Organisation name
                if (!empty($entity['handle']) && empty($fields['org'])) {
                    // Try vcard fn first, then handle
                    $fields['org'] = $vcard['fn'] ?? $entity['handle'];
                }

                // If it's a registration entity, try to get organisation from vcard
                if ($is_org && empty($fields['org'])) {
                    $fields['org'] = $vcard['fn'] ?? $entity['handle'] ?? '';
                }

                // Person name
                if (empty($fields['person']) && !empty($vcard['fn'])) {
                    // Only set if not already used as org (check if roles suggest person)
                    if ($is_tech || $is_billing || $is_abuse) {
                        $fields['person'] = $vcard['fn'];
                    }
                }

                // Email
                if (empty($fields['email']) && !empty($vcard['email'])) {
                    $fields['email'] = $vcard['email'];
                }

                // Country (take first found)
                if (empty($fields['country']) && !empty($vcard['country'])) {
                    $fields['country'] = $vcard['country'];
                }

                // Remarks from entity remarks
                if (empty($fields['remarks']) && !empty($entity['remarks'])) {
                    $remarks_text = [];
                    foreach ($entity['remarks'] as $remark) {
                        if (!empty($remark['description'])) {
                            $remarks_text[] = implode("\n", $remark['description']);
                        }
                    }
                    if (!empty($remarks_text)) {
                        $fields['remarks'] = implode(' | ', $remarks_text);
                    }
                }
            }
        }

        // Also try top-level remarks
        if (empty($fields['remarks']) && !empty($data['remarks'])) {
            $remarks_text = [];
            foreach ($data['remarks'] as $remark) {
                if (!empty($remark['description'])) {
                    $remarks_text[] = implode("\n", $remark['description']);
                }
            }
            if (!empty($remarks_text)) {
                $fields['remarks'] = implode(' | ', $remarks_text);
            }
        }

        // Country from top-level if not found yet
        if (empty($fields['country']) && !empty($data['country'])) {
            $fields['country'] = $data['country'];
        }

        return $fields;
    }

    /**
     * Parse a jCard (vCard JSON) array and extract key fields.
     *
     * @param array $vcardArray The vcardArray from RDAP response
     * @return array ['fn' => '', 'email' => '', 'country' => '']
     */
    private static function parse_vcard(array $vcardArray): array {
        $result = [
            'fn'      => '',
            'email'   => '',
            'country' => '',
        ];

        // vcardArray format: ["vcard", [ [...] ]]
        if (empty($vcardArray[0]) || $vcardArray[0] !== 'vcard') {
            return $result;
        }

        $cards = $vcardArray[1] ?? [];
        foreach ($cards as $card) {
            foreach ($card as $prop) {
                if (!is_array($prop) || count($prop) < 3) {
                    continue;
                }
                $prop_name = strtolower($prop[0] ?? '');
                $prop_value = $prop[3] ?? '';

                switch ($prop_name) {
                    case 'fn':
                        if (empty($result['fn'])) {
                            $result['fn'] = is_string($prop_value) ? $prop_value : '';
                        }
                        break;
                    case 'email':
                        if (empty($result['email'])) {
                            if (is_string($prop_value)) {
                                $result['email'] = $prop_value;
                            } elseif (is_array($prop_value)) {
                                // Sometimes email value is buried in an array
                                $result['email'] = $prop_value[0] ?? '';
                            }
                        }
                        break;
                    case 'adr':
                        // Address: structure, country is usually the last element
                        if (empty($result['country']) && is_array($prop_value)) {
                            $pieces = $prop_value;
                            $last = end($pieces);
                            if (is_string($last) && strlen($last) === 2) {
                                $result['country'] = $last;
                            }
                        }
                        break;
                }
            }
        }

        return $result;
    }
}