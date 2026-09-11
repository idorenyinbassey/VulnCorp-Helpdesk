<?php
require_once dirname(__FILE__) . '/../includes/auth.php';
require_once dirname(__FILE__) . '/../includes/db.php';
require_login();

// ---------------------------------------------------------------
// Static download templates. These are pre-generated files (not
// rendered by PHP) sitting under assets/toolkit/<format>/. Kept static
// on purpose: this app targets PHP 5.2 for the Metasploitable2 deploy,
// and there's no good docx/xlsx library for PHP that old, so these are
// built once with modern tooling and just served as plain downloads.
// ---------------------------------------------------------------
$templates = array(
    array(
        'slug' => 'safe-testing-rules',
        'title' => 'Safe Testing Rules',
        'desc' => 'One-pager rules of engagement — what to check before testing, what to avoid while testing, and the red lines that apply no matter what program you\'re on.',
    ),
    array(
        'slug' => 'program-policy-check',
        'title' => 'Program Policy Check',
        'desc' => 'Pre-engagement checklist: scope, rules, rewards/process, and legal terms to review before you start testing a bug bounty program.',
    ),
    array(
        'slug' => 'program-signal-sheet',
        'title' => 'Program Signal Sheet',
        'desc' => 'Quick triage sheet — responsiveness, reputation, and scope health — to decide whether a program is worth your time before you invest hours in it.',
    ),
    array(
        'slug' => 'recon-note-template',
        'title' => 'Recon Note Template',
        'desc' => 'Structured notes for passive recon, active recon, and application mapping, ending in a hypotheses-to-test list.',
    ),
    array(
        'slug' => 'web-app-test-checklist',
        'title' => 'Web App Test Checklist',
        'desc' => 'The 12 vulnerability categories from the Tools Reference / methodology sections above, as a fillable tested/result/severity/notes table.',
    ),
    array(
        'slug' => 'report-writing-template',
        'title' => 'Report Writing Template',
        'desc' => 'Title, severity, steps to reproduce, PoC, impact, remediation — the standard shape of a real bug bounty report.',
    ),
    array(
        'slug' => 'severity-cheat-sheet',
        'title' => 'Severity Cheat Sheet',
        'desc' => 'Critical/High/Medium/Low/Informational definitions with concrete examples, plus the one-line test to sanity-check your own rating.',
    ),
);

$formats = array(
    'md' => array('ext' => 'md', 'label' => '.md'),
    'docx' => array('ext' => 'docx', 'label' => '.docx'),
    'doc' => array('ext' => 'doc', 'label' => '.doc'),
    'xlsx' => array('ext' => 'xlsx', 'label' => '.xlsx'),
    'xls' => array('ext' => 'xls', 'label' => '.xls'),
);

include dirname(__FILE__) . '/../includes/header.php';
?>
<h2>Toolkit — Checklists &amp; Kits</h2>
<p class="small">Downloadable templates for real (authorized) engagements — the paperwork side of the
methodology from the Challenges page. Every template is available in five formats; grab whichever fits
how you work.</p>

<?php foreach ($templates as $t): ?>
<div style="border:1px solid #e5e7eb;border-radius:6px;padding:14px 18px;margin-bottom:14px;background:#fff;">
    <strong><?php echo htmlspecialchars($t['title']); ?></strong>
    <p class="small" style="margin:6px 0 10px;"><?php echo htmlspecialchars($t['desc']); ?></p>
    <div>
    <?php foreach ($formats as $key => $f): ?>
        <a class="btn" style="margin:0 6px 6px 0;padding:5px 12px;font-size:13px;"
           href="<?php echo app_base(); ?>/assets/toolkit/<?php echo $key; ?>/<?php echo $t['slug']; ?>.<?php echo $f['ext']; ?>"
           download><?php echo $f['label']; ?></a>
    <?php endforeach; ?>
    </div>
</div>
<?php endforeach; ?>

<p class="small">These are static files, not generated per-request — edit them locally after downloading
and keep your own copy. If you update the source content, regenerate all five formats together so they
stay in sync.</p>

<?php include dirname(__FILE__) . '/../includes/footer.php'; ?>
