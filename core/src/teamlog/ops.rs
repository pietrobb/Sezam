//! The team log's operations behind [`crate::json::call`]. A rule refusing
//! a record is an answer (`{"refused": {code, seq, detail}}`), not an error;
//! an error is bad input.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::{json, Map, Value};

use super::canonical::{canonical, parse_body};
use super::{fork, replay, rules, LogResult, State};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplayIn {
    records: Vec<Value>,
    state: Option<State>,
    /// how many of the checks passed from the start; left out: the first run
    verified: Option<usize>,
    /// the state after each record, not only the last
    #[serde(default)]
    steps: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectIn {
    state: State,
    kind: String,
    author: String,
    data: Map<String, Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Question {
    #[serde(rename = "fn")]
    name: String,
    args: Vec<Value>,
}

/// The state a question is about: given whole, or one loaded before.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AskIn {
    state: Option<State>,
    handle: Option<u64>,
    questions: Vec<Question>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RejudgeIn {
    state: State,
    body: Map<String, Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoadIn {
    state: State,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HandleIn {
    handle: u64,
}

/// States loaded for many questions (review 8bc70f7 M8: a 40 000-folder
/// state took 130 ms to read per question). A side frees what it loads.
static LOADED: Mutex<(u64, BTreeMap<u64, Arc<State>>)> = Mutex::new((0, BTreeMap::new()));

fn loaded() -> std::sync::MutexGuard<'static, (u64, BTreeMap<u64, Arc<State>>)> {
    LOADED
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn load(state: State) -> u64 {
    let mut store = loaded();
    store.0 += 1;
    let handle = store.0;
    store.1.insert(handle, Arc::new(state));
    handle
}

/// A state a side loaded (`team_log_load`), for the other modules' questions.
pub fn loaded_state(handle: u64) -> Result<Arc<State>, String> {
    get(handle)
}

fn get(handle: u64) -> Result<Arc<State>, String> {
    loaded()
        .1
        .get(&handle)
        .cloned()
        .ok_or_else(|| format!("no loaded team log state {handle}"))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ForkIn {
    lost: Vec<Value>,
    theirs: Vec<Value>,
    user_id: Option<String>,
    held_keys: Option<(String, String)>,
    withdrawn: BTreeSet<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AbandonedIn {
    lost: Vec<Value>,
    user_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PartsIn {
    bodies: Vec<Map<String, Value>>,
    start: usize,
    limit: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadmittedIn {
    bodies: Vec<Map<String, Value>>,
    index: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ValueIn {
    value: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BodyIn {
    body: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordIn {
    body: String,
    sig: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewKeyIn {
    prev: String,
    user_id: String,
    signing_pk: String,
    encryption_pk: String,
}

fn answer<T: serde::Serialize>(result: LogResult<T>, name: &str) -> Value {
    match result {
        Ok(value) => json!({ name: value }),
        Err(e) => json!({"refused": e.to_json()}),
    }
}

fn arg_str<'a>(args: &'a [Value], i: usize, name: &str) -> Result<&'a str, String> {
    args.get(i)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{name}: argument {i} is not a string"))
}

fn arg_opt<'a>(args: &'a [Value], i: usize, name: &str) -> Result<Option<&'a str>, String> {
    match args.get(i) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s)),
        _ => Err(format!("{name}: argument {i} is not a string or null")),
    }
}

fn arg_bool(args: &[Value], i: usize, name: &str, default: Option<bool>) -> Result<bool, String> {
    match (args.get(i), default) {
        (Some(Value::Bool(b)), _) => Ok(*b),
        (None, Some(d)) => Ok(d),
        _ => Err(format!("{name}: argument {i} is not a boolean")),
    }
}

fn arity(args: &[Value], name: &str, min: usize, max: usize) -> Result<(), String> {
    if args.len() < min || args.len() > max {
        return Err(format!(
            "{name}: takes {min}..={max} arguments, got {}",
            args.len()
        ));
    }
    Ok(())
}

/// One question about a state, as the decision vectors ask it.
pub fn ask(state: &State, name: &str, args: &[Value]) -> Result<Value, String> {
    let s = |i| arg_str(args, i, name);
    let o = |i| arg_opt(args, i, name);
    let n = |min, max| arity(args, name, min, max);
    Ok(match name {
        "state_json" => {
            n(0, 0)?;
            state.to_json()
        }
        "is_team_folder" => {
            n(1, 1)?;
            json!(rules::is_team_folder(state, s(0)?))
        }
        "current_key" => {
            n(1, 1)?;
            json!(rules::current_key(state, s(0)?))
        }
        "key_generation" => {
            n(2, 2)?;
            let (kind, gen) = rules::key_generation(state, s(0)?, s(1)?);
            json!([kind, gen])
        }
        "is_stale" => {
            n(1, 1)?;
            json!(rules::is_stale(state, s(0)?))
        }
        "may_seal" => {
            n(1, 1)?;
            json!(rules::may_seal(state, s(0)?))
        }
        "is_admin" => {
            n(1, 1)?;
            json!(rules::is_admin(state, s(0)?))
        }
        "recovery_key" => {
            n(1, 1)?;
            json!(rules::recovery_key(state, s(0)?))
        }
        "recovery_wrap" => {
            n(1, 1)?;
            json!(rules::recovery_wrap(state, s(0)?))
        }
        "may_write" => {
            n(2, 2)?;
            json!(rules::may_write(state, s(0)?, s(1)?))
        }
        "key_recipients" => {
            n(1, 1)?;
            json!(rules::key_recipients(state, s(0)?))
        }
        "may_hold_key" => {
            n(2, 2)?;
            json!(rules::may_hold_key(state, s(0)?, s(1)?))
        }
        "item_refusal" => {
            n(5, 6)?;
            json!(rules::item_refusal(
                state,
                s(0)?,
                s(1)?,
                o(2)?,
                o(3)?,
                arg_bool(args, 4, name, None)?,
                arg_bool(args, 5, name, Some(true))?,
            ))
        }
        "admin_policy_refusal" => {
            n(0, 0)?;
            json!(rules::admin_policy_refusal(state))
        }
        "signing_key_retired" => {
            n(2, 2)?;
            json!(rules::signing_key_retired(state, s(0)?, s(1)?))
        }
        "todays_rules_refusal" => {
            n(1, 1)?;
            let body = args[0]
                .as_object()
                .ok_or_else(|| format!("{name}: the body is not an object"))?;
            json!(rules::todays_rules_refusal(state, body))
        }
        "tombstone_refusal" => {
            n(2, 2)?;
            json!(rules::tombstone_refusal(state, s(0)?, o(1)?))
        }
        "move_refusal" => {
            n(3, 4)?;
            json!(rules::move_refusal(
                state,
                s(0)?,
                o(1)?,
                o(2)?,
                arg_bool(args, 3, name, Some(false))?,
            ))
        }
        "envelope_valid" => {
            n(5, 5)?;
            json!(rules::envelope_valid(
                state,
                s(0)?,
                s(1)?,
                s(2)?,
                o(3)?,
                s(4)?
            ))
        }
        "superseded_envelope_valid" => {
            n(4, 4)?;
            json!(rules::superseded_envelope_valid(
                state,
                s(0)?,
                s(1)?,
                s(2)?,
                s(3)?
            ))
        }
        "next_body" => {
            n(3, 3)?;
            json!(rules::next_body(state, s(0)?, s(1)?, &args[2]))
        }
        "resolve_change" => {
            n(2, 2)?;
            answer(
                super::resolve::resolve_change(state, s(0)?, &args[1]),
                "data",
            )
        }
        _ => return Err(format!("unknown team log question {name:?}")),
    })
}

/// The `team_log_*` operations; None: not one of them.
pub fn run(op: &str, input: &str) -> Option<Result<Value, String>> {
    fn parse<T: DeserializeOwned>(input: &str) -> Result<T, String> {
        serde_json::from_str(input).map_err(|e| format!("bad input: {e}"))
    }
    if !op.starts_with("team_log_") {
        return None;
    }
    let out = (|| -> Result<Value, String> {
        Ok(match op {
            "team_log_replay" => {
                let i: ReplayIn = parse(input)?;
                match (i.verified, i.steps) {
                    (None, _) => json!({"checks": replay::checks(&i.records, i.state.as_ref())}),
                    (Some(n), false) => {
                        answer(replay::replay(&i.records, i.state.as_ref(), n), "state")
                    }
                    (Some(n), true) => {
                        match replay::replay_steps(&i.records, i.state.as_ref(), n) {
                            Ok((state, steps)) => json!({"state": state, "steps": steps}),
                            Err(e) => json!({"refused": e.to_json()}),
                        }
                    }
                }
            }
            "team_log_project" => {
                let i: ProjectIn = parse(input)?;
                answer(
                    replay::apply_change(&i.state, &i.kind, &i.author, &i.data),
                    "state",
                )
            }
            "team_log_ask" => {
                let i: AskIn = parse(input)?;
                let state = match (i.state, i.handle) {
                    (Some(state), None) => Arc::new(state),
                    (None, Some(handle)) => get(handle)?,
                    _ => return Err("bad input: name either state or handle".into()),
                };
                let answers = i
                    .questions
                    .iter()
                    .map(|q| ask(&state, &q.name, &q.args))
                    .collect::<Result<Vec<_>, _>>()?;
                json!(answers)
            }
            "team_log_rejudge" => {
                let i: RejudgeIn = parse(input)?;
                json!(replay::rejudge(&i.state, &i.body).map(|e| e.to_json()))
            }
            "team_log_load" => {
                let i: LoadIn = parse(input)?;
                json!(load(i.state))
            }
            "team_log_free" => {
                let i: HandleIn = parse(input)?;
                json!(loaded().1.remove(&i.handle).is_some())
            }
            "team_log_fork" => {
                let i: ForkIn = parse(input)?;
                let held = i.held_keys.as_ref().map(|(a, b)| (a.as_str(), b.as_str()));
                answer(
                    fork::fork_refusal(
                        &i.lost,
                        &i.theirs,
                        i.user_id.as_deref(),
                        held,
                        &i.withdrawn,
                    )
                    .map(|(refusal, missing)| json!({"refusal": refusal, "missing": missing})),
                    "fork",
                )
            }
            "team_log_abandoned" => {
                let i: AbandonedIn = parse(input)?;
                answer(
                    fork::fork_abandoned(&i.lost, i.user_id.as_deref()),
                    "hashes",
                )
            }
            "team_log_restore_part_end" => {
                let i: PartsIn = parse(input)?;
                json!(fork::restore_part_end(&i.bodies, i.start, i.limit))
            }
            "team_log_readmitted" => {
                let i: ReadmittedIn = parse(input)?;
                json!(fork::readmitted(&i.bodies, i.index))
            }
            "team_log_canonical" => {
                let i: ValueIn = parse(input)?;
                answer(canonical(&i.value, None), "text")
            }
            "team_log_parse_body" => {
                let i: BodyIn = parse(input)?;
                answer(parse_body(&i.body, None), "body")
            }
            "team_log_change_key" => {
                let i: BodyIn = parse(input)?;
                answer(
                    parse_body(&i.body, None).and_then(|b| fork::change_key(&b)),
                    "key",
                )
            }
            "team_log_record_hash" => {
                let i: RecordIn = parse(input)?;
                json!(replay::record_hash(&i.body, &i.sig))
            }
            "team_log_new_key_message" => {
                let i: NewKeyIn = parse(input)?;
                json!(super::to_hex(&replay::new_key_message(
                    &i.prev,
                    &i.user_id,
                    &i.signing_pk,
                    &i.encryption_pk
                )))
            }
            "team_log_sig_message" => {
                let i: BodyIn = parse(input)?;
                if !i.body.is_ascii() {
                    return Err("a record body is ASCII text".to_string());
                }
                json!(super::to_hex(&replay::sig_message(&i.body)))
            }
            "team_log_follow_plan" => super::follow::plan(parse(input)?),
            "team_log_follow_served" => super::follow::served(parse(input)?),
            "team_log_follow_caught_up" => super::follow::caught_up(parse(input)?),
            "team_log_mismatch_causes" => super::follow::causes(),
            "team_log_fork_follows" => super::fork_follow::follows(parse(input)?),
            "team_log_fork_split" => super::fork_follow::split(parse(input)?),
            "team_log_fork_take" => super::fork_follow::take(parse(input)?),
            "team_log_empty_state" => json!(State::default()),
            _ => return Err(format!("unknown operation {op:?}")),
        })
    })();
    Some(out)
}
