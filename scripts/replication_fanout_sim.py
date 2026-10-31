#!/usr/bin/env python3
"""Compare idealized synchronous push-pull schedules, not Kuipa or agirru."""

import argparse
import hashlib
import json
import random
import statistics
import sys
from pathlib import Path


def simulate(size, fanout, loss, seed):
    """Spread one bit using simultaneous round snapshots and independent loss."""
    rng = random.Random(seed)
    known = {0}
    attempts = successes = useful_sessions = 0
    for round_number in range(1, 1001):
        before = known
        after = before.copy()
        for sender in range(size):
            # Sample without allocating an N-element peer list for every contact.
            for index in rng.sample(range(size - 1), fanout):
                peer = index + (index >= sender)
                attempts += 1
                if loss and rng.random() < loss:
                    continue
                successes += 1
                if (sender in before) != (peer in before):
                    useful_sessions += 1
                    after.add(sender)
                    after.add(peer)
        known = after
        if len(known) == size:
            assert 0 <= useful_sessions <= successes <= attempts
            return {
                "seed": seed,
                "converged": True,
                "rounds": round_number,
                "attempts": attempts,
                "successes": successes,
                "lost": attempts - successes,
                "useful_sessions": useful_sessions,
                "newly_informed": size - 1,
            }
    return {
        "seed": seed,
        "converged": False,
        "rounds": 1000,
        "attempts": attempts,
        "successes": successes,
        "lost": attempts - successes,
        "useful_sessions": useful_sessions,
        "newly_informed": len(known) - 1,
    }


def simulate_partition(size, fanout, sweep_interval, loss, partition_rounds, seed):
    """Rotate shuffled peers through a partition and optional all-peer sweeps."""
    rng = random.Random(seed)
    peers = []
    for sender in range(size):
        order = list(range(size))
        order.remove(sender)
        rng.shuffle(order)
        peers.append(order)
    offsets = [0] * size
    known = {0}
    attempts = blocked = lost = successes = sweep_attempts = sweeps = 0
    for round_number in range(1, 1001):
        before = known
        after = before.copy()
        sweeping = sweep_interval > 0 and round_number % sweep_interval == 0
        if sweeping:
            sweeps += 1
        for sender in range(size):
            if sweeping:
                selected = (peer for peer in range(size) if peer != sender)
            else:
                start = offsets[sender]
                end = min(start + fanout, size - 1)
                selected = peers[sender][start:end]
                offsets[sender] = end
                if end == size - 1:
                    rng.shuffle(peers[sender])
                    offsets[sender] = 0
            for peer in selected:
                attempts += 1
                if sweeping:
                    sweep_attempts += 1
                if round_number <= partition_rounds and (sender < size // 2) != (peer < size // 2):
                    blocked += 1
                    continue
                if loss and rng.random() < loss:
                    lost += 1
                    continue
                successes += 1
                if (sender in before) != (peer in before):
                    after.add(sender)
                    after.add(peer)
        known = after
        if len(known) == size:
            assert round_number > partition_rounds
            assert attempts == blocked + lost + successes
            return {
                "seed": seed,
                "converged": True,
                "rounds": round_number,
                "rounds_after_heal": round_number - partition_rounds,
                "attempts": attempts,
                "blocked": blocked,
                "lost": lost,
                "successes": successes,
                "sweeps": sweeps,
                "sweep_attempts": sweep_attempts,
            }
    return {"seed": seed, "converged": False, "rounds": 1000, "informed": len(known)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=2119)
    parser.add_argument("--repetitions", type=int, default=5)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.repetitions < 1:
        parser.error("--repetitions must be positive")

    check = simulate(2, 1, 0.0, args.seed)
    assert (check["rounds"], check["attempts"], check["newly_informed"]) == (1, 2, 1)
    repair_check = simulate_partition(2, 1, 1, 0.0, 1, args.seed)
    assert (repair_check["rounds"], repair_check["blocked"], repair_check["attempts"]) == (2, 2, 4)
    scenarios = []
    for size in (60, 100, 200, 300):
        for fanout in (4, 8, size - 1):
            for loss in (0.0, 0.1):
                runs = [simulate(size, fanout, loss, args.seed + run) for run in range(args.repetitions)]
                assert all(run["converged"] for run in runs), "round limit reached"
                scenarios.append({
                    "replicas": size,
                    "fanout": fanout,
                    "loss_probability": loss,
                    "median_rounds": statistics.median(run["rounds"] for run in runs),
                    "median_attempts": statistics.median(run["attempts"] for run in runs),
                    "runs": runs,
                })
    repair_scenarios = []
    for size in (60, 100, 200, 300):
        for fanout in (4, 8):
            for sweep_interval in (0, 5, 10):
                for loss in (0.0, 0.1):
                    runs = [
                        simulate_partition(size, fanout, sweep_interval, loss, 6, args.seed + run)
                        for run in range(args.repetitions)
                    ]
                    assert all(run["converged"] for run in runs), "round limit reached"
                    repair_scenarios.append({
                        "replicas": size,
                        "fanout": fanout,
                        "sweep_interval_rounds": sweep_interval,
                        "partition_rounds": 6,
                        "loss_probability": loss,
                        "median_rounds_after_heal": statistics.median(run["rounds_after_heal"] for run in runs),
                        "median_attempts": statistics.median(run["attempts"] for run in runs),
                        "runs": runs,
                    })
    result = {
        "kind": "idealized_synchronous_push_pull_simulation",
        "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "python": sys.version.split()[0],
        "seed": args.seed,
        "repetitions": args.repetitions,
        "assumptions": "One update; every node contacts distinct randomly sampled peers each round, including nodes with no update; successful contacts exchange the bit both ways using start-of-round snapshots; independent per-session loss; fixed complete membership. No bytes, authentication, state sizes, persistence, repair sweep, latency or engine implementation.",
        "partition_assumptions": "One update starts in the first half; two equal halves cannot contact each other for six rounds, followed by full connectivity; all nodes initiate every round; rotating random peer permutations with no repeated peers within a cycle, at most fanout contacts per round; optional synchronized all-peer sweeps every five or ten rounds; blocked contacts fail before independent per-session loss; zero sweep interval disables sweeps. No engine, payload sizes, bytes, authentication, durable storage or elapsed time.",
        "repair_scenarios": repair_scenarios,
        "scenarios": scenarios,
    }
    text = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.write_text(text, encoding="utf-8")
    else:
        print(text, end="")


if __name__ == "__main__":
    main()
