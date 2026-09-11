<?php
require_once dirname(__FILE__) . '/../includes/auth.php';
require_once dirname(__FILE__) . '/../includes/db.php';
require_login();

$msg = '';
$err = '';
$tiers = array('simple', 'intermediate', 'hard', 'expert');
$selected_tier = isset($_GET['tier']) && in_array($_GET['tier'], $tiers, true) ? $_GET['tier'] : $tiers[0];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $tier = in_array($_POST['tier'], $tiers, true) ? $_POST['tier'] : null;
    $difficulty_rating = isset($_POST['difficulty_rating']) ? (int)$_POST['difficulty_rating'] : 0;
    $concept_clarity_rating = isset($_POST['concept_clarity_rating']) ? (int)$_POST['concept_clarity_rating'] : 0;
    $hint_usefulness_rating = isset($_POST['hint_usefulness_rating']) ? (int)$_POST['hint_usefulness_rating'] : 0;
    $confidence_rating = isset($_POST['confidence_rating']) ? (int)$_POST['confidence_rating'] : 0;
    $most_confusing = isset($_POST['most_confusing']) ? $_POST['most_confusing'] : '';
    $other_comments = isset($_POST['other_comments']) ? $_POST['other_comments'] : '';

    $ratings_ok = $tier
        && $difficulty_rating >= 1 && $difficulty_rating <= 5
        && $concept_clarity_rating >= 1 && $concept_clarity_rating <= 5
        && $hint_usefulness_rating >= 1 && $hint_usefulness_rating <= 5
        && $confidence_rating >= 1 && $confidence_rating <= 5;

    if (!$ratings_ok) {
        $err = 'Please rate every question from 1 to 5 and pick a tier.';
        $selected_tier = isset($_POST['tier']) ? $_POST['tier'] : $selected_tier;
    } else {
        $username = $_SESSION['username'];
        $stmt = mysqli_prepare($conn,
            "INSERT INTO module_survey
                (username, tier, difficulty_rating, concept_clarity_rating, hint_usefulness_rating, confidence_rating, most_confusing, other_comments)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)
             ON DUPLICATE KEY UPDATE
                difficulty_rating = VALUES(difficulty_rating),
                concept_clarity_rating = VALUES(concept_clarity_rating),
                hint_usefulness_rating = VALUES(hint_usefulness_rating),
                confidence_rating = VALUES(confidence_rating),
                most_confusing = VALUES(most_confusing),
                other_comments = VALUES(other_comments)");
        mysqli_stmt_bind_param($stmt, 'ssiiiiss', $username, $tier,
            $difficulty_rating, $concept_clarity_rating, $hint_usefulness_rating, $confidence_rating,
            $most_confusing, $other_comments);
        mysqli_stmt_execute($stmt);
        $msg = 'Thanks — your feedback for the ' . htmlspecialchars($tier) . ' tier has been recorded.';
        $selected_tier = $tier;
    }
}

// Pre-fill with any existing answer for the selected tier so re-submitting updates it.
$existing = null;
$stmt = mysqli_prepare($conn, "SELECT * FROM module_survey WHERE username = ? AND tier = ?");
mysqli_stmt_bind_param($stmt, 'ss', $_SESSION['username'], $selected_tier);
mysqli_stmt_execute($stmt);
$existing = stmt_fetch_one($stmt);

function survey_scale($name, $label, $existing) {
    $current = $existing ? (int)$existing[$name] : 0;
    echo '<p>' . htmlspecialchars($label) . '</p><div style="margin-bottom:14px;">';
    for ($i = 1; $i <= 5; $i++) {
        $checked = ($i === $current) ? 'checked' : '';
        echo '<label style="margin-right:14px;font-weight:normal;">';
        echo '<input type="radio" name="' . htmlspecialchars($name) . '" value="' . $i . '" ' . $checked . ' required style="width:auto;"> ' . $i;
        echo '</label>';
    }
    echo '</div>';
}

include dirname(__FILE__) . '/../includes/header.php';
?>
<h2>Module Feedback</h2>
<p class="small">A few quick questions after working through a tier — this helps improve the lab for the
next group of students. Answers are visible to admins only.</p>
<?php if ($msg): ?><div class="notice"><?php echo $msg; ?></div><?php endif; ?>
<?php if ($err): ?><div class="error"><?php echo htmlspecialchars($err); ?></div><?php endif; ?>

<form method="POST" style="max-width:520px;">
    <label>Which tier are you giving feedback on?</label>
    <select name="tier_switch" onchange="window.location.href='<?php echo htmlspecialchars(app_base()); ?>/feedback/survey.php?tier=' + this.value">
        <?php foreach ($tiers as $t): ?>
        <option value="<?php echo $t; ?>" <?php if ($t === $selected_tier) echo 'selected'; ?>><?php echo ucfirst($t); ?></option>
        <?php endforeach; ?>
    </select>
    <input type="hidden" name="tier" value="<?php echo htmlspecialchars($selected_tier); ?>">
    <p class="small">(changing this reloads the page with your existing answer for that tier, if any)</p>

    <?php
    survey_scale('difficulty_rating', 'Overall difficulty of this tier (1 = way too easy, 5 = way too hard)', $existing);
    survey_scale('concept_clarity_rating', 'How clear were the "Why this works" explanations? (1 = confusing, 5 = very clear)', $existing);
    survey_scale('hint_usefulness_rating', 'How useful were the Nudge/Full answer hints? (1 = not useful, 5 = very useful)', $existing);
    survey_scale('confidence_rating', 'How confident do you feel explaining this tier\'s bugs to someone else? (1 = not at all, 5 = very)', $existing);
    ?>

    <label>What confused you most in this tier? (optional)</label>
    <textarea name="most_confusing" rows="3"><?php echo $existing ? htmlspecialchars($existing['most_confusing']) : ''; ?></textarea>

    <label>Anything else? (optional)</label>
    <textarea name="other_comments" rows="3"><?php echo $existing ? htmlspecialchars($existing['other_comments']) : ''; ?></textarea>

    <button type="submit">Submit Feedback</button>
</form>

<?php include dirname(__FILE__) . '/../includes/footer.php'; ?>
