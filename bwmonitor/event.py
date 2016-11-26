from ryu.controller.ofp_event import event

#EventOfFlowOccur
#EventOfFlowRemoved
#EventOfFlowAppTypeRecognized
#EventOfFlowQoSChanged

class EventOfFlowRemoved(event.EventBase):
    def __init__(self,flow=None):
        super(EventOfFlowRemoved,self).__init__()
        self.flow = flow
