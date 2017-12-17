import React from 'react';
import { WebView, StyleSheet, Text, View } from 'react-native';

export default class App extends React.Component {
  render() {
    return (
      <WebView
        source={{uri: 'https://noahle.com/infosec/index.html'}}
        style={{marginTop: 20}}
      />
    );
  }
}

const styles = StyleSheet.create({

});
