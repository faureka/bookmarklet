import React from 'react';
import Card from '../components/Card.jsx';

export default class ListView extends React.Component {
    render() {
        return (
            <div style={{width:'800' + 'px', margin:'0'+" "+ 'auto'}}>
                <Card />
                <Card />
                <Card />
            </div>
        )
    }
}