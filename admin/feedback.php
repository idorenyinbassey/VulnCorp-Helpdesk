<?php
require_once dirname(__FILE__) . '/../includes/auth.php';
require_once dirname(__FILE__) . '/../includes/db.php';
require_role('admin');

// ---- Per-challenge vote aggregation, worst-first so hotspots surface immediately ----
$stmt = mysqli_prepare($conn, "
    SELECT
        challenge_id,
        SUM(rating = 'too_easy') AS too_easy,
        SUM(rating = 'just_right') AS just_right,
        SUM(rating = 'too_hard') AS too_hard,
        SUM(rating = 'stuck') AS stuck,
        COUNT(*) AS total
    FROM challenge_feedback
    GROUP BY challenge_id
    ORDER BY (SUM(rating = 'too_hard') + SUM(rating = 'stuck')) DESC, total DESC
");
mysqli_stmt_execute($stmt);
$challenge_rows = stmt_fetch_all($stmt);

// ---- Survey aggregation per tier ----
$stmt = mysqli_prepare($conn, "
    SELECT
        tier,
        COUNT(*) AS responses,
        AVG(difficulty_rating) AS avg_difficulty,
        AVG(concept_clarity_rating) AS avg_clarity,
        AVG(hint_usefulness_rating) AS avg_hints,
        AVG(confidence_rating) AS avg_confidence
    FROM module_survey
    GROUP BY tier
    ORDER BY FIELD(tier, 'simple', 'intermediate', 'hard', 'expert')
");
mysqli_stmt_execute($stmt);
$survey_summary = stmt_fetch_all($stmt);

// ---- Individual survey responses with free-text comments ----
$stmt = mysqli_prepare($conn, "
    SELECT username, tier, difficulty_rating, concept_clarity_rating, hint_usefulness_rating,
           confidence_rating, most_confusing, other_comments, submitted_at
    FROM module_survey
    WHERE most_confusing != '' OR other_comments != ''
    ORDER BY submitted_at DESC
");
mysqli_stmt_execute($stmt);
$survey_comments = stmt_fetch_all($stmt);

function fmt1($n) { return number_format((float)$n, 1); }

include dirname(__FILE__) . '/../includes/header.php';
?>
<h2>Student Feedback Results</h2>
<p class="small">Admin-only. Sourced from the per-challenge quick-votes on the Challenges page and the
end-of-tier survey at <code>/feedback/survey.php</code>.</p>

<h3>Challenge hotspots</h3>
<p class="small">Sorted worst-first (most "too hard" + "stuck" votes at the top) — these are the
challenges most likely to need a clearer hint, an easier nudge, or a difficulty re-rating.</p>
<?php if (empty($challenge_rows)): ?>
<p class="small">No votes recorded yet.</p>
<?php else: ?>
<table>
<tr><th>Challenge</th><th>Too easy</th><th>Just right</th><th>Too hard</th><th>Stuck</th><th>Total</th></tr>
<?php foreach ($challenge_rows as $r): ?>
<tr<?php if ((int)$r['too_hard'] + (int)$r['stuck'] > (int)$r['just_right']) echo ' style="background:#fef2f2;"'; ?>>
    <td><code><?php echo htmlspecialchars($r['challenge_id']); ?></code></td>
    <td><?php echo (int)$r['too_easy']; ?></td>
    <td><?php echo (int)$r['just_right']; ?></td>
    <td><?php echo (int)$r['too_hard']; ?></td>
    <td><?php echo (int)$r['stuck']; ?></td>
    <td><?php echo (int)$r['total']; ?></td>
</tr>
<?php endforeach; ?>
</table>
<p class="small">Rows highlighted red have more "too hard"/"stuck" votes than "just right" ones.</p>
<?php endif; ?>

<h3 style="margin-top:30px;">Survey averages by tier</h3>
<?php if (empty($survey_summary)): ?>
<p class="small">No survey responses yet.</p>
<?php else: ?>
<table>
<tr><th>Tier</th><th>Responses</th><th>Avg. difficulty (1-5)</th><th>Avg. concept clarity (1-5)</th><th>Avg. hint usefulness (1-5)</th><th>Avg. confidence (1-5)</th></tr>
<?php foreach ($survey_summary as $s): ?>
<tr>
    <td><?php echo htmlspecialchars(ucfirst($s['tier'])); ?></td>
    <td><?php echo (int)$s['responses']; ?></td>
    <td><?php echo fmt1($s['avg_difficulty']); ?></td>
    <td><?php echo fmt1($s['avg_clarity']); ?></td>
    <td><?php echo fmt1($s['avg_hints']); ?></td>
    <td><?php echo fmt1($s['avg_confidence']); ?></td>
</tr>
<?php endforeach; ?>
</table>
<?php endif; ?>

<h3 style="margin-top:30px;">Free-text comments</h3>
<?php if (empty($survey_comments)): ?>
<p class="small">No comments left yet.</p>
<?php else: ?>
<?php foreach ($survey_comments as $c): ?>
<div style="border:1px solid #e5e7eb;border-radius:6px;padding:10px 14px;margin-bottom:10px;">
    <strong><?php echo htmlspecialchars($c['username']); ?></strong>
    <span class="small"> — <?php echo htmlspecialchars(ucfirst($c['tier'])); ?> tier ·
    difficulty <?php echo (int)$c['difficulty_rating']; ?>/5, confidence <?php echo (int)$c['confidence_rating']; ?>/5 ·
    <?php echo htmlspecialchars($c['submitted_at']); ?></span>
    <?php if ($c['most_confusing'] !== ''): ?>
    <p><strong>Most confusing:</strong> <?php echo nl2br(htmlspecialchars($c['most_confusing'])); ?></p>
    <?php endif; ?>
    <?php if ($c['other_comments'] !== ''): ?>
    <p><strong>Other:</strong> <?php echo nl2br(htmlspecialchars($c['other_comments'])); ?></p>
    <?php endif; ?>
</div>
<?php endforeach; ?>
<?php endif; ?>

<?php include dirname(__FILE__) . '/../includes/footer.php'; ?>
