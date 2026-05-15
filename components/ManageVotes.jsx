import React, { useState } from 'react';
import { Box, Button, H3, Text, Input, Label, FormGroup, NoticeBox } from '@adminjs/design-system';
import { useNotice, ApiClient } from 'adminjs';

const api = new ApiClient();

const ManageVotes = (props) => {
  const { record, resource } = props;
  const addNotice = useNotice();

  // Local state for the override form
  const [workingCount, setWorkingCount] = useState(record.params.workingVoteCount || 0);
  const [notWorkingCount, setNotWorkingCount] = useState(record.params.notWorkingVoteCount || 0);
  const [isLoading, setIsLoading] = useState(false);

  // Function to handle the form submission
  const handleSubmit = (actionType) => {
    // Basic confirmation for the reset action
    if (actionType === 'reset' && !window.confirm("Are you sure you want to permanently delete all user votes for this mod?")) {
        return;
    }

    setIsLoading(true);

    // Call the custom action endpoint on the server
    api.resourceAction({
      resourceId: resource.id,
      actionName: 'manageVotes',
      recordId: record.id,
      method: 'post',
      data: {
        actionType: actionType,
        newWorkingCount: workingCount,
        newNotWorkingCount: notWorkingCount
      }
    }).then(response => {
      setIsLoading(false);
      // AdminJS will automatically handle the notice and redirect based on what we returned from the server!
      if (response.data.notice) {
        addNotice(response.data.notice);
      }
      if (response.data.redirectUrl) {
         window.location.href = response.data.redirectUrl;
      }
    }).catch(error => {
      setIsLoading(false);
      addNotice({ message: 'An error occurred while contacting the server.', type: 'error' });
    });
  };

  return (
    <Box variant="white" p="xl" style={{ backgroundColor: '#1a1a1a', borderRadius: '8px', border: '1px solid #333' }}>
      
      <H3 style={{ color: '#FFD700', marginBottom: '20px' }}>Manage Votes for: {record.params.name}</H3>
      
      <NoticeBox style={{ marginBottom: '30px' }}>
        <strong>Current Status:</strong><br/>
        Working Votes: <span style={{ color: '#43a047', fontWeight: 'bold' }}>{record.params.workingVoteCount || 0}</span><br/>
        Not Working Votes: <span style={{ color: '#e53935', fontWeight: 'bold' }}>{record.params.notWorkingVoteCount || 0}</span>
      </NoticeBox>

      {/* --- OPTION 1: FULL RESET --- */}
      <Box mb="xxl" p="lg" style={{ border: '1px solid #444', borderRadius: '8px', backgroundColor: '#0a0a0a' }}>
        <H3 style={{ color: '#ffffff', fontSize: '1.2em' }}>Option 1: Reset All Votes</H3>
        <Text style={{ color: '#c0c0c0', marginBottom: '15px' }}>
          This will wipe all existing user votes and reset both counts to 0. This is highly recommended when a major update is released that fixes a broken mod.
        </Text>
        <Button 
            variant="danger" 
            onClick={() => handleSubmit('reset')} 
            disabled={isLoading}
        >
          {isLoading ? 'Processing...' : 'Wipe & Reset Votes to 0'}
        </Button>
      </Box>

      {/* --- OPTION 2: MANUAL OVERRIDE --- */}
      <Box p="lg" style={{ border: '1px solid #444', borderRadius: '8px', backgroundColor: '#0a0a0a' }}>
        <H3 style={{ color: '#ffffff', fontSize: '1.2em' }}>Option 2: Manually Override Counts</H3>
        <Text style={{ color: '#ffadad', marginBottom: '15px', fontSize: '0.9em' }}>
          Warning: Manually setting numbers will clear the internal list of users who voted. Use this only if you need to artificially boost or reduce a score.
        </Text>
        
        <Box flex style={{ gap: '20px', marginBottom: '20px' }}>
            <FormGroup style={{ flex: 1 }}>
                <Label style={{ color: '#c0c0c0' }}>Force "Working" Count</Label>
                <Input 
                    type="number" 
                    value={workingCount} 
                    onChange={(e) => setWorkingCount(e.target.value)} 
                    style={{ backgroundColor: '#1a1a1a', color: 'white', border: '1px solid #333' }}
                />
            </FormGroup>
            
            <FormGroup style={{ flex: 1 }}>
                <Label style={{ color: '#c0c0c0' }}>Force "Not Working" Count</Label>
                <Input 
                    type="number" 
                    value={notWorkingCount} 
                    onChange={(e) => setNotWorkingCount(e.target.value)}
                    style={{ backgroundColor: '#1a1a1a', color: 'white', border: '1px solid #333' }}
                />
            </FormGroup>
        </Box>

        <Button 
            variant="primary" 
            onClick={() => handleSubmit('override')} 
            disabled={isLoading}
            style={{ backgroundColor: '#FFD700', color: 'black', border: 'none' }}
        >
          {isLoading ? 'Processing...' : 'Apply Manual Override'}
        </Button>
      </Box>

    </Box>
  );
};

export default ManageVotes;