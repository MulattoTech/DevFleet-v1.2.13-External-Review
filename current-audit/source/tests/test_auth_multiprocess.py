import json
import multiprocessing

from devfleet import auth


def _issue_session_in_process(queue):
    from devfleet.auth import issue_session
    queue.put(issue_session("test")[0])


def test_sessions_json_is_safe_for_separate_worker_processes():
    path = auth._session_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{}\n", encoding="utf-8")
    ctx = multiprocessing.get_context("spawn")
    queue = ctx.Queue()
    workers = [ctx.Process(target=_issue_session_in_process, args=(queue,)) for _ in range(4)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(20)
    assert all(worker.exitcode == 0 for worker in workers)
    records = json.loads(path.read_text(encoding="utf-8"))
    assert len(records) == 4
    for worker in workers:
        worker.close()
