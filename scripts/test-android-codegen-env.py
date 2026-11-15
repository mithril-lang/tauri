#!/usr/bin/env python3
"""Exercise real Tauri build scripts against a shared Cargo target, without a device.

Use the published tauri 3.0.0-alpha.6 source as --baseline-crate. Its build.rs
must differ from this checkout only by the reviewed environment tracking patch.
The caller must exclusively own and serialize access to --target-dir; the harness
validates its location but cannot prove ownership or inter-process exclusion.
The private --stage receives a disposable source copy, lockfile and build logs.
No shipping dependency, installed app or credentials are changed. Only the
selected caller-owned target cache may be reused.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
VARIABLES = ('WRY_ANDROID_KOTLIN_FILES_OUT_DIR', 'WRY_ANDROID_PACKAGE',
             'WRY_ANDROID_LIBRARY', 'TAURI_ANDROID_PROJECT_PATH',
             'TAURI_ANDROID_PACKAGE_UNESCAPED')


def main(args):
    if not __debug__:
        raise ValueError('optimized Python disables assertions; run without -O/PYTHONOPTIMIZE')
    def check_source():
        source = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
        dirty = subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT)
        if source != args.source or dirty:
            raise ValueError('clean fixed source checkout required')
    check_source()
    stage = args.stage.resolve()
    if stage.exists() or ROOT in stage.parents or args.baseline_crate.resolve() in stage.parents:
        raise ValueError('fresh private stage required; never reuse another run')
    checksums = json.loads((args.baseline_crate / '.cargo-checksum.json').read_text())
    for name, expected in checksums['files'].items():
        if hashlib.sha256((args.baseline_crate / name).read_bytes()).hexdigest() != expected:
            raise ValueError('baseline package content differs: ' + name)
    stage.mkdir(mode=0o700)
    crate = stage / 'tauri'
    shutil.copytree(args.baseline_crate, crate,
                    ignore=shutil.ignore_patterns('target', 'build', '.gradle'))
    baseline = (crate / 'build.rs').read_bytes()
    fixed = (ROOT / 'crates/tauri/build.rs').read_bytes()
    if hashlib.sha256(fixed).hexdigest() != args.fixed_build_sha256:
        raise ValueError('fixed build script differs from trusted caller fingerprint')
    if hashlib.sha256(baseline).hexdigest() != 'd3e34b25ac35f605501d24faa9286167cfa8482b5a48fb9c6fae5d76912daf4f':
        raise ValueError('expected published alpha.6 build-script source')
    if baseline == fixed:
        raise ValueError('baseline must be the unpatched published build script')
    shutil.copy2(args.seed_lock, crate / 'Cargo.lock')
    target = args.target_dir or stage / 'target'
    if not target.is_absolute() or target.resolve() != target or target == ROOT or ROOT in target.parents:
        raise ValueError('qualified absolute Cargo target outside checkout required')
    env = os.environ.copy()
    for key in VARIABLES:
        env.pop(key, None)
    env.update(CARGO_TARGET_DIR=str(target), CARGO_BUILD_JOBS='2', RUSTUP_AUTO_INSTALL='0')
    kotlin_a, kotlin_b = stage / 'kotlin-a', stage / 'kotlin-b'
    project_a, project_b = stage / 'project-a', stage / 'project-b'
    for path in (kotlin_a, kotlin_b, project_a / 'app', project_b / 'app'):
        path.mkdir(parents=True)
    env.update(WRY_ANDROID_KOTLIN_FILES_OUT_DIR=str(kotlin_a),
               WRY_ANDROID_PACKAGE='fund.fixture.alpha', WRY_ANDROID_LIBRARY='fixture_alpha',
               TAURI_ANDROID_PROJECT_PATH=str(project_a),
               TAURI_ANDROID_PACKAGE_UNESCAPED='fund.fixture.alpha')
    count = 0

    def build(name, expected_success=True, locked=True, missing_variable=None):
        nonlocal count
        command = [str(args.cargo), 'check', '--offline', '--no-default-features',
                   '--target', 'aarch64-linux-android', '--manifest-path', str(crate / 'Cargo.toml')]
        if locked:
            command.append('--locked')
        with (stage / (name + '.log')).open('wb') as log:
            result = subprocess.run(command, env=env, stdout=log, stderr=subprocess.STDOUT)
        if (result.returncode == 0) != expected_success:
            raise AssertionError(name + ': unexpected Cargo outcome; inspect private log')
        if missing_variable and ('`' + missing_variable + '` is not set') not in (stage / (name + '.log')).read_text():
            raise AssertionError(name + ': failed for an unrelated reason')
        count += 1

    def check_outputs():
        if env.get('WRY_ANDROID_KOTLIN_FILES_OUT_DIR'):
            directory = Path(env['WRY_ANDROID_KOTLIN_FILES_OUT_DIR'])
            for template in (crate / 'mobile/android-codegen').iterdir():
                expected = template.read_text().replace('{{package}}', env['WRY_ANDROID_PACKAGE'])
                expected = expected.replace('{{library}}', env['WRY_ANDROID_LIBRARY'])
                assert (directory / template.name).read_text() == expected, template.name
        if env.get('TAURI_ANDROID_PROJECT_PATH'):
            expected = (crate / 'mobile/proguard-tauri.pro').read_text().replace(
                '$PACKAGE', env.get('TAURI_ANDROID_PACKAGE_UNESCAPED', env['WRY_ANDROID_PACKAGE'].replace('`', '')))
            assert (Path(env['TAURI_ANDROID_PROJECT_PATH']) / 'app/proguard-tauri.pro').read_text() == expected

    build('baseline-a', locked=False)
    check_outputs()
    # The baseline watches its own generated file. Its first write can itself
    # cause one extra Cargo run; settle that before changing either destination.
    # Otherwise that unrelated initial rerun can mask the missing env watches.
    build('baseline-a-warm-control')
    check_outputs()
    env['WRY_ANDROID_KOTLIN_FILES_OUT_DIR'] = str(kotlin_b)
    env['TAURI_ANDROID_PROJECT_PATH'] = str(project_b)
    build('baseline-b-missing-output')
    assert not (kotlin_b / 'TauriActivity.kt').exists(), 'baseline no longer reproduces the bug'
    assert not (project_b / 'app/proguard-tauri.pro').exists()
    (crate / 'build.rs').write_bytes(fixed)
    build('fixed-b')
    check_outputs()
    for key, value in [('WRY_ANDROID_PACKAGE', 'fund.fixture.beta'),
                       ('WRY_ANDROID_LIBRARY', 'fixture_beta'),
                       ('TAURI_ANDROID_PACKAGE_UNESCAPED', 'fund.fixture.raw')]:
        env[key] = value
        build('change-' + key)
        check_outputs()
    for key in VARIABLES:
        value = env.pop(key)
        invalid = key in ('WRY_ANDROID_PACKAGE', 'WRY_ANDROID_LIBRARY')
        build('unset-' + key, expected_success=not invalid, missing_variable=key if invalid else None)
        if not invalid:
            check_outputs()
        env[key] = value
        build('restore-' + key)
        check_outputs()
    check_source()
    receipt = {'source': args.source, 'cargoRuns': count, 'baselineFailureReproduced': True,
           'fixedBuildScriptSha256': hashlib.sha256(fixed).hexdigest(),
           'qualification': 'Android build-script component only; no APK/device/release claim'}
    with (stage / 'receipt.json').open('x') as output:
        json.dump(receipt, output, sort_keys=True)
    print(receipt)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline-crate', type=Path, required=True)
    parser.add_argument('--seed-lock', type=Path, required=True)
    parser.add_argument('--stage', type=Path, required=True)
    parser.add_argument('--cargo', type=Path, required=True)
    parser.add_argument('--source', required=True)
    parser.add_argument('--fixed-build-sha256', required=True)
    parser.add_argument('--target-dir', type=Path,
                        help='optional caller-owned cache; serialize access, preserve prior runs')
    main(parser.parse_args())
