import evtx_parser
import sys

def main(evtx_path):
    print(f"Dumping EventIDs from {evtx_path}:")
    for event in evtx_parser.parse_evtx(evtx_path):
        # Print all possible ways EventID might be stored
        event_id = event.get('EventID') or event.get('event_id') or event.get('Id')
        system = event.get('System', {})
        if isinstance(system, dict):
            sys_id = system.get('EventID')
            if isinstance(sys_id, dict):
                sys_id = sys_id.get('#text')
        else:
            sys_id = None
            
        print(f"EventID: {event_id}, System.EventID: {sys_id}, Keys: {list(event.keys())}")

if __name__ == "__main__":
    main(sys.argv[1])
