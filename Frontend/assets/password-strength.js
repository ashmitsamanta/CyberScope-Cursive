/**
 * ============================================================================
 * CyberScope Password Strength Evaluator & UI Meter
 * Author: Senior Full Stack Developer (15+ YOE)
 * Description: Real-time password security grading on a 0-10 scale.
 * Features:
 *   - 10-point scoring algorithm (Length, Diversity, Entropy & Pattern Checks)
 *   - Letter Grades (A+, A, B+, B, C, D, F) & Level Ratings (STRONG, MEDIUM, WEAK)
 *   - Dynamic color-coded UI bar (Vibrant Green for Strong, Amber for Medium, Red for Weak)
 *   - Interactive accessibility & real-time feedback loop
 * ============================================================================
 */

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.PasswordStrength = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // Common leaked or default passwords set for instant fail penalty
  const COMMON_PASSWORDS = new Set([
    "password", "password1", "password123", "123456", "12345678",
    "qwerty", "qwerty123", "letmein", "admin", "welcome",
    "iloveyou", "monkey", "dragon", "111111", "abc123",
    "passw0rd", "password1!", "p@ssword", "p@ssw0rd", "000000",
    "admin123", "master", "sunshine", "princess", "charlie"
  ]);

  const SPECIAL_CHARS = '!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~';

  /**
   * Helper: Detects sequential ascending (abc, 123) or repeated (aaa, 111) character runs
   */
  function hasRepeatedOrSequentialRun(pw, runLen) {
    runLen = runLen || 3;
    if (!pw || pw.length < runLen) return false;
    for (let i = 0; i <= pw.length - runLen; i++) {
      const slice = pw.slice(i, i + runLen);
      // Repeated run (e.g. "aaa")
      if (new Set(slice).size === 1) return true;
      // Sequential run (e.g. "123", "abc")
      let isSequential = true;
      for (let j = 0; j < slice.length - 1; j++) {
        if (slice.charCodeAt(j) + 1 !== slice.charCodeAt(j + 1)) {
          isSequential = false;
          break;
        }
      }
      if (isSequential) return true;
    }
    return false;
  }

  /**
   * Evaluates password strength on a 0 - 10 numerical scale and assigns a grade.
   * @param {string} pw - Password to analyze
   * @returns {Object} Evaluation report containing score out of 10, grade, rating, color, and reasons.
   */
  function evaluatePassword(pw) {
    const maxScore = 10;
    const reasons = [];
    const checks = {
      lengthOk: false,
      hasLower: false,
      hasUpper: false,
      hasDigit: false,
      hasSpecial: false,
      noSequential: true
    };

    if (!pw || typeof pw !== 'string' || pw.length === 0) {
      return {
        score: 0,
        maxScore: maxScore,
        grade: 'F',
        rating: 'WEAK',
        levelClass: 'weak',
        color: 'var(--pw-red, #ff6b7a)',
        percentage: 0,
        reasons: ['Password cannot be empty.'],
        checks: checks,
        acceptable: false
      };
    }

    // Instant fail for dictionary / common passwords
    if (COMMON_PASSWORDS.has(pw.toLowerCase())) {
      reasons.push("This password appears on common compromised lists. Choose something unpredictable.");
      return {
        score: 0,
        maxScore: maxScore,
        grade: 'F',
        rating: 'WEAK',
        levelClass: 'weak',
        color: 'var(--pw-red, #ff6b7a)',
        percentage: 10,
        reasons: reasons,
        checks: checks,
        acceptable: false
      };
    }

    let score = 0;
    const len = pw.length;

    // 1. Length Evaluation (Up to 4 points out of 10)
    if (len >= 16) {
      score += 4;
      checks.lengthOk = true;
    } else if (len >= 12) {
      score += 3;
      checks.lengthOk = true;
    } else if (len >= 8) {
      score += 2;
      checks.lengthOk = true;
      reasons.push("Password length is acceptable, but 12+ characters provide much stronger security.");
    } else {
      reasons.push("Password is too short. Minimum 8 characters required (12+ recommended).");
    }

    // 2. Character Variety (Up to 4 points out of 10)
    if (/[a-z]/.test(pw)) {
      score += 1;
      checks.hasLower = true;
    } else {
      reasons.push("Add at least one lowercase letter (a-z).");
    }

    if (/[A-Z]/.test(pw)) {
      score += 1;
      checks.hasUpper = true;
    } else {
      reasons.push("Add at least one uppercase letter (A-Z).");
    }

    if (/\d/.test(pw)) {
      score += 1;
      checks.hasDigit = true;
    } else {
      reasons.push("Add at least one numeric digit (0-9).");
    }

    let hasSpecial = false;
    for (let i = 0; i < len; i++) {
      if (SPECIAL_CHARS.includes(pw[i])) {
        hasSpecial = true;
        break;
      }
    }
    if (hasSpecial) {
      score += 1;
      checks.hasSpecial = true;
    } else {
      reasons.push("Add at least one special character (!@#$%^&*).");
    }

    // 3. Complexity & Entropy Bonuses (Up to 2 points out of 10)
    const varietyCount = [checks.hasLower, checks.hasUpper, checks.hasDigit, checks.hasSpecial].filter(Boolean).length;
    if (varietyCount === 4) {
      score += 1; // Full set bonus
    }
    if (len >= 14 && varietyCount >= 3) {
      score += 1; // High entropy length bonus
    }

    // 4. Pattern / Predictability Deductions
    if (hasRepeatedOrSequentialRun(pw, 3)) {
      checks.noSequential = false;
      reasons.push("Avoid repeated or sequential characters (e.g. 'aaa', '123', 'abc').");
      score = Math.max(0, score - 1);
    }

    // Bound score strictly between 0 and 10
    score = Math.min(maxScore, Math.max(0, score));

    // Determine Letter Grade out of 10
    let grade = 'F';
    let rating = 'WEAK';
    let levelClass = 'weak';
    let color = 'var(--pw-red, #ff6b7a)'; // Default Red for Weak

    if (score >= 9) {
      grade = score === 10 ? 'A+' : 'A';
      rating = 'STRONG';
      levelClass = 'strong';
      color = 'var(--pw-green, #5dffb1)'; // Green for Strong
    } else if (score >= 7) {
      grade = score === 8 ? 'B+' : 'B';
      rating = 'STRONG';
      levelClass = 'strong';
      color = 'var(--pw-green-light, #34d399)'; // Emerald/Green for Strong
    } else if (score >= 5) {
      grade = 'C';
      rating = 'MEDIUM';
      levelClass = 'medium';
      color = 'var(--pw-amber, #ffb84d)'; // Yellow/Amber for Medium
    } else if (score >= 3) {
      grade = 'D';
      rating = 'WEAK';
      levelClass = 'weak';
      color = 'var(--pw-orange, #ff8c42)'; // Orange-Red for Weak
    } else {
      grade = 'F';
      rating = 'WEAK';
      levelClass = 'weak';
      color = 'var(--pw-red, #ff6b7a)'; // Red for Weak
    }

    const percentage = Math.max(8, Math.round((score / maxScore) * 100));

    return {
      score: score,
      maxScore: maxScore,
      grade: grade,
      rating: rating,
      levelClass: levelClass,
      color: color,
      percentage: percentage,
      reasons: reasons,
      checks: checks,
      acceptable: score >= 5
    };
  }

  /**
   * Renders or updates the Password Strength meter component in DOM.
   * @param {HTMLElement|string} container - Container DOM element or selector
   * @param {Object} evalData - Report object returned by evaluatePassword
   */
  function renderMeter(container, evalData) {
    const el = typeof container === 'string' ? document.querySelector(container) : container;
    if (!el) return;

    el.style.display = 'block';
    el.setAttribute('data-rating', evalData.rating);
    el.setAttribute('data-grade', evalData.grade);
    el.setAttribute('aria-valuenow', evalData.score);
    el.setAttribute('aria-valuemin', 0);
    el.setAttribute('aria-valuemax', 10);

    // Update rating badge & grade display
    const ratingEl = el.querySelector('.pw-rating-text') || el.querySelector('#pwRating');
    const scoreEl = el.querySelector('.pw-score-text') || el.querySelector('#pwScore');
    const gradeBadge = el.querySelector('.pw-grade-badge') || el.querySelector('#pwGrade');
    const fillEl = el.querySelector('.pw-strength-bar-fill') || el.querySelector('.pw-bar-fill');
    const reasonsEl = el.querySelector('.pw-strength-reasons') || el.querySelector('#pwReasons');

    if (ratingEl) {
      ratingEl.textContent = evalData.rating;
      ratingEl.style.color = evalData.color;
    }

    if (scoreEl) {
      scoreEl.textContent = `Score: ${evalData.score} / ${evalData.maxScore}`;
    }

    if (gradeBadge) {
      gradeBadge.textContent = `Grade ${evalData.score}/10 (${evalData.grade})`;
      gradeBadge.className = `pw-grade-badge grade-${evalData.levelClass}`;
      gradeBadge.style.color = evalData.color;
      gradeBadge.style.borderColor = evalData.color;
    }

    if (fillEl) {
      fillEl.style.width = `${evalData.percentage}%`;
      fillEl.style.backgroundColor = evalData.color;
      fillEl.style.boxShadow = `0 0 10px ${evalData.color}66`;
    }

    if (reasonsEl) {
      reasonsEl.innerHTML = '';
      if (evalData.reasons.length === 0) {
        const li = document.createElement('li');
        li.className = 'pw-tip-success';
        li.innerHTML = '<span class="icon">✓</span> Optimal security — password meets top-tier grade standard.';
        reasonsEl.appendChild(li);
      } else {
        evalData.reasons.forEach(function (reason) {
          const li = document.createElement('li');
          li.className = 'pw-tip-warning';
          li.innerHTML = `<span class="icon">⚠</span> ${reason}`;
          reasonsEl.appendChild(li);
        });
      }
    }
  }

  /**
   * Initializes real-time listener on password input field.
   * @param {HTMLElement|string} inputEl - Target password input
   * @param {HTMLElement|string} meterContainer - Target strength display container
   */
  function attachToInput(inputEl, meterContainer) {
    const input = typeof inputEl === 'string' ? document.querySelector(inputEl) : inputEl;
    const container = typeof meterContainer === 'string' ? document.querySelector(meterContainer) : meterContainer;
    if (!input || !container) return;

    function handleInput() {
      const val = input.value;
      if (!val) {
        container.style.display = 'none';
        return;
      }
      const evalData = evaluatePassword(val);
      renderMeter(container, evalData);
    }

    input.addEventListener('input', handleInput);
    if (input.value) handleInput();
  }

  return {
    evaluate: evaluatePassword,
    render: renderMeter,
    attach: attachToInput,
    COMMON_PASSWORDS: COMMON_PASSWORDS
  };
}));
